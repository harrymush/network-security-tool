# Network Security Tool

A comprehensive network security analysis tool with a modern GUI interface.

## Features

- **Network Tools**
  - IP range scanning with customizable timeout and quick scan options
  - Port scanning with service detection and banner grabbing
  - Customizable scan parameters (threads, delay, timeout)
  - Real-time progress tracking and statistics
  - Results filtering (active/inactive hosts)
  - Export scan results

- **Packet Sniffer**
  - Interface selection with auto-refresh
  - BPF filter support
  - Real-time packet capture
  - Detailed packet analysis
  - Statistics tracking

- **SSL/TLS Analyzer** (warning: issue with this tool)
  - Certificate inspection and validation
  - Protocol detection and analysis
  - Security assessment
  - Vulnerability checking
  - Certificate verification options
  - Export capabilities

- **Vulnerability Scanner**
  - Web application scanning
  - Network vulnerability assessment
  - Customizable scan parameters
  - Detailed vulnerability reporting

- **Password Tools**
  - Password Analysis
    - Strength assessment
    - Security recommendations
  - Password Generator
    - Customizable length and character sets
    - Special character options
    - Exclude similar/ambiguous characters
  - Passphrase Generator
    - Word count customization
    - Separator options
    - Case and number options
  - Password Cracker
    - Multiple hash format support
    - Dictionary attacks
    - Brute force capability
    - Custom dictionary support
  - Hash Converter
    - Multiple hash algorithm support (MD5, SHA1, SHA256, SHA512)
    - Copy to clipboard functionality

  - **Web Cracker**
    - Form-based authentication testing
    - Multiple attack strategies
    - Custom wordlist support
    - Multi-threaded operations
    - Real-time progress monitoring

## Installation

1. Clone the repository:
```bash
git clone https://github.com/harrymush/network-security-tool.git
cd network-security-tool
```

2. Install the package:
```bash
pip install -e .
```

## Usage

Run the application:
```bash
network-security-tool
```

Or directly from the source:
```bash
python -m network_security_tool
```

## Requirements

- Python 3.8 or higher
- PyQt6
- python-nmap
- dnspython
- python-whois
- cryptography
- requests
- scapy
- matplotlib
- numpy

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Security

This tool is designed for educational and testing purposes only. Use responsibly and only on networks and systems you have permission to test. The authors are not responsible for any misuse or damage caused by this tool.

## Safe Testing Guidelines

To ensure responsible usage of this tool, here are approved targets and methods for testing:

### Safe DNS and Network Testing Targets

| Domain             | Purpose                         |
|--------------------|----------------------------------|
| `example.com`      | General test domain             |
| `example.org`      | General test domain             |
| `example.net`      | General test domain             |
| `test.com`         | Reserved for testing            |
| `invalid.`         | Invalid domain (RFC 6761)       |
| `localhost`        | Localhost testing               |

### Reserved IP Ranges for Testing

These ranges are reserved for testing and don't route to the internet (RFC 5737):

| CIDR               | Range            | Purpose             |
|--------------------|------------------|----------------------|
| `192.0.2.0/24`     | `192.0.2.1-254`  | TEST-NET-1 (docs)    |
| `198.51.100.0/24`  | `198.51.100.1-254` | TEST-NET-2         |
| `203.0.113.0/24`   | `203.0.113.1-254` | TEST-NET-3         |
| `127.0.0.1`        | Loopback         | Local testing       |
| `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12` | Private networks |

### SSL/TLS Testing Resources

Test your SSL/TLS analyzer against various certificate configurations using [badssl.com](https://badssl.com/):

- `https://expired.badssl.com/`
- `https://self-signed.badssl.com/`
- `https://wrong.host.badssl.com/`
- `https://sha1-intermediate.badssl.com/`

### Web Security Testing

For web vulnerability testing and web cracking, use these deliberately vulnerable environments:

| Name                         | Use Case                              | URL |
|------------------------------|----------------------------------------|-----|
| **OWASP Juice Shop**         | Web vuln testing, brute force, XSS    | [owasp.org/www-project-juice-shop](https://owasp.org/www-project-juice-shop/) |
| **DVWA**                     | SQLi, XSS, CSRF, etc.                 | [github.com/digininja/DVWA](https://github.com/digininja/DVWA) |
| **bWAPP**                    | Over 100 web bugs                     | [github.com/raesene/bwapp](https://github.com/raesene/bwapp) |
| **VulnHub VMs**              | Full-stack VMs for testing            | [vulnhub.com](https://vulnhub.com) |

### Password Testing Resources

For password tools testing, use these non-sensitive test data:

```bash
# Test password: "password123"
MD5:    482c811da5d5b4bc6d497ffa98491e38  
SHA1:   cbfdac6008f9cab4083784cbd1874f76618d2a97  
SHA256: ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
```

Recommended wordlists:
- [SecLists](https://github.com/danielmiessler/SecLists)
- [CrackStation's Wordlist](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)

### Ethical Usage Note

This tool is for educational and authorized testing purposes only. Always use the approved test targets listed above when demonstrating or testing the tool's capabilities. Never run this tool against live systems without explicit permission.

## Use Cases and Applications

### 1. Network Security (Defensive / Blue Team)
Network administrators and security defenders can use this tool to:

- Scan local networks to identify unauthorized devices or misconfigured hosts
- Analyze DNS records of internal/external domains to check for spoofing or leaks
- Sniff packets to inspect traffic flow or investigate anomalies
- Inspect SSL/TLS certificates for expiry, bad encryption, or misconfigurations
- Generate strong passwords and passphrases for securing user accounts
- Hash analysis and conversion to investigate stored credentials in logs or config files

**Primary Use**: Proactive system hardening, policy auditing, and threat detection.

### 2. Ethical Hacking (Red Team & Self-Assessments)
Ethical hackers (with permission) can use this tool to:

- Perform reconnaissance on target systems (via DNS, SSL, and port scanning)
- Identify vulnerabilities in test environments (using the vulnerability scanner)
- Run web application tests to find insecure login forms or input fields
- Use the web cracker module for fuzzing, brute-forcing, or session testing
- Analyze password strength and try cracking hashes from test data or CTFs

**Primary Use**: Responsible vulnerability discovery and red team simulations.

### 3. Penetration Testing (Authorized Exploitation)
In a legal penetration testing engagement or lab environment, the tool helps you:

- Fingerprint a target network or domain
- Extract DNS records for possible subdomains and misconfigurations
- Perform SSL/TLS audits for weak encryption or invalid certificates
- Find open ports and services that might be exploitable
- Launch test brute-force or fuzzing attacks against test login pages
- Crack hashes and passwords in offline test environments

**Primary Use**: Simulating attacker behavior and helping clients fix real-world weaknesses.


### Important Note on Usage

This tool is for educational and authorized use only!
Never scan, sniff, crack, or test systems you do not own or have explicit permission to target.

We recommend using:

Local test environments (e.g., VirtualBox, Docker)

Legal targets like DVWA, OWASP Juice Shop, and VulnHub boxes

Reserved test domains (example.com) and IPs (192.0.2.0/24)
