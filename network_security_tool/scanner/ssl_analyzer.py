import socket
import ssl
from OpenSSL import SSL, crypto
from datetime import datetime
from typing import Dict, List, Optional, Callable

class SSLAnalyzer:
    def __init__(self):
        self._is_running = False
        
    def analyze_ssl(self, host: str, port: int = 443,
                   callback: Optional[Callable[[str], None]] = None) -> List[Dict]:
        """
        Analyze SSL/TLS configuration of a host.
        
        Args:
            host: Hostname or IP address
            port: Port number (default: 443)
            callback: Optional callback function to receive results in real-time
            
        Returns:
            List of dictionaries containing SSL analysis results
        """
        self._is_running = True
        results = []
        
        try:
            # Create SSL context
            context = SSL.Context(SSL.TLSv1_2_METHOD)
            
            # Create socket and wrap with SSL
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            ssl_sock = SSL.Connection(context, sock)
            
            # Connect to host
            ssl_sock.connect((host, port))
            ssl_sock.do_handshake()
            
            # Get certificate
            cert = ssl_sock.get_peer_certificate()
            
            # Analyze certificate
            cert_info = self._analyze_certificate(cert)
            results.append(cert_info)
            if callback:
                callback(f"Certificate analysis complete")
                
            # Check SSL/TLS configuration
            config_info = self._check_ssl_config(ssl_sock)
            results.append(config_info)
            if callback:
                callback(f"SSL configuration analysis complete")
                
            # Check for common vulnerabilities
            vuln_info = self._check_vulnerabilities(ssl_sock)
            results.extend(vuln_info)
            if callback:
                callback(f"Vulnerability check complete")
                
        except Exception as e:
            result = {
                "error": f"SSL analysis failed: {str(e)}"
            }
            results.append(result)
            if callback:
                callback(f"Error: {str(e)}")
                
        finally:
            try:
                ssl_sock.close()
                sock.close()
            except:
                pass
                
        return results
        
    def _analyze_certificate(self, cert: crypto.X509) -> Dict:
        """Analyze SSL certificate."""
        result = {
            "type": "certificate",
            "subject": dict(cert.get_subject().get_components()),
            "issuer": dict(cert.get_issuer().get_components()),
            "version": cert.get_version(),
            "serial_number": cert.get_serial_number(),
            "not_before": cert.get_notBefore().decode(),
            "not_after": cert.get_notAfter().decode(),
            "signature_algorithm": cert.get_signature_algorithm().decode(),
            "public_key_bits": cert.get_pubkey().bits(),
            "public_key_type": cert.get_pubkey().type()
        }
        
        # Check certificate expiration
        not_after = datetime.strptime(result["not_after"], "%Y%m%d%H%M%SZ")
        if not_after < datetime.now():
            result["status"] = "expired"
        else:
            result["status"] = "valid"
            
        return result
        
    def _check_ssl_config(self, ssl_sock: SSL.Connection) -> Dict:
        """Check SSL/TLS configuration."""
        result = {
            "type": "configuration",
            "protocol": ssl_sock.get_protocol_version_name(),
            "cipher": ssl_sock.get_cipher_name(),
            "compression": ssl_sock.get_current_compression_method()
        }
        
        # Check for weak protocols
        weak_protocols = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
        if result["protocol"] in weak_protocols:
            result["status"] = "weak"
        else:
            result["status"] = "secure"
            
        return result
        
    def _check_vulnerabilities(self, ssl_sock: SSL.Connection) -> List[Dict]:
        """Check for common SSL/TLS vulnerabilities."""
        results = []
        
        # Check for Heartbleed vulnerability
        try:
            ssl_sock.send(b"\x18\x03\x02\x00\x03\x01\x40\x00")
            response = ssl_sock.recv(1024)
            if len(response) > 0:
                results.append({
                    "type": "vulnerability",
                    "name": "Heartbleed",
                    "status": "vulnerable",
                    "severity": "critical"
                })
        except:
            results.append({
                "type": "vulnerability",
                "name": "Heartbleed",
                "status": "not vulnerable",
                "severity": "none"
            })
            
        # Check for POODLE vulnerability
        try:
            ssl_sock.send(b"\x80\x00\x00\x00\x00\x00\x00\x00")
            response = ssl_sock.recv(1024)
            if len(response) > 0:
                results.append({
                    "type": "vulnerability",
                    "name": "POODLE",
                    "status": "vulnerable",
                    "severity": "high"
                })
        except:
            results.append({
                "type": "vulnerability",
                "name": "POODLE",
                "status": "not vulnerable",
                "severity": "none"
            })
            
        return results
        
    def stop(self):
        """Stop the current analysis."""
        self._is_running = False 