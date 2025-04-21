import socket
import ssl
import OpenSSL
from datetime import datetime
from typing import Dict, List, Optional
import re

class SSLAnalyzer:
    def __init__(self):
        self.results = {}
        
    def analyze_host(self, host: str, port: int = 443) -> Dict:
        """Analyze SSL/TLS configuration of a host"""
        self.results = {
            "host": host,
            "port": port,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "certificate": {},
            "protocols": [],
            "ciphers": [],
            "vulnerabilities": [],
            "error": None
        }
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Try different SSL/TLS versions
            for protocol in [ssl.PROTOCOL_TLS, ssl.PROTOCOL_TLSv1_2, ssl.PROTOCOL_TLSv1_1, ssl.PROTOCOL_TLSv1]:
                try:
                    with socket.create_connection((host, port)) as sock:
                        with context.wrap_socket(sock, server_hostname=host) as ssock:
                            # Get certificate info
                            cert = ssock.getpeercert()
                            cert_info = ssl.get_server_certificate((host, port))
                            x509 = OpenSSL.crypto.load_certificate(
                                OpenSSL.crypto.FILETYPE_PEM, cert_info
                            )
                            
                            # Store certificate details
                            self.results["certificate"] = {
                                "subject": dict(x509.get_subject().get_components()),
                                "issuer": dict(x509.get_issuer().get_components()),
                                "version": x509.get_version() + 1,
                                "serial_number": hex(x509.get_serial_number())[2:],
                                "not_before": x509.get_notBefore().decode('ascii'),
                                "not_after": x509.get_notAfter().decode('ascii'),
                                "signature_algorithm": x509.get_signature_algorithm().decode('ascii'),
                                "public_key_bits": x509.get_pubkey().bits(),
                                "public_key_type": x509.get_pubkey().type() == OpenSSL.crypto.TYPE_RSA
                            }
                            
                            # Get supported protocols
                            self.results["protocols"].append(ssock.version())
                            
                            # Get cipher info
                            cipher = ssock.cipher()
                            if cipher:
                                self.results["ciphers"].append({
                                    "name": cipher[0],
                                    "version": cipher[1],
                                    "bits": cipher[2]
                                })
                                
                            # Check for vulnerabilities
                            self._check_vulnerabilities(ssock, x509)
                            
                except ssl.SSLError as e:
                    continue
                except Exception as e:
                    self.results["error"] = str(e)
                    return self.results
                    
            return self.results
            
        except Exception as e:
            self.results["error"] = str(e)
            return self.results
            
    def _check_vulnerabilities(self, ssock: ssl.SSLSocket, cert: OpenSSL.crypto.X509) -> None:
        """Check for common SSL/TLS vulnerabilities"""
        # Check certificate expiration
        not_after = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%S%z')
        if (not_after - datetime.now(not_after.tzinfo)).days < 30:
            self.results["vulnerabilities"].append({
                "type": "Certificate",
                "severity": "Medium",
                "description": "SSL certificate expires soon",
                "details": f"Certificate expires on {not_after.strftime('%Y-%m-%d')}"
            })
            
        # Check for weak protocols
        if ssock.version() in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
            self.results["vulnerabilities"].append({
                "type": "Protocol",
                "severity": "High",
                "description": f"Insecure SSL/TLS version: {ssock.version()}",
                "details": "Older SSL/TLS versions have known vulnerabilities"
            })
            
        # Check for weak ciphers
        cipher = ssock.cipher()
        if cipher:
            if cipher[2] < 128:  # Check key length
                self.results["vulnerabilities"].append({
                    "type": "Cipher",
                    "severity": "High",
                    "description": "Weak cipher suite",
                    "details": f"Cipher {cipher[0]} uses {cipher[2]}-bit keys"
                })
                
        # Check certificate signature algorithm
        if cert.get_signature_algorithm().decode('ascii').startswith(b"md5"):
            self.results["vulnerabilities"].append({
                "type": "Certificate",
                "severity": "High",
                "description": "Weak certificate signature algorithm",
                "details": "MD5-based signatures are vulnerable to collision attacks"
            })
            
    def get_results(self) -> Dict:
        """Get the analysis results"""
        return self.results 