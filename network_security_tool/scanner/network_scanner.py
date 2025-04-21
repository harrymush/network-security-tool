import socket
import threading
import queue
import time
from typing import List, Dict, Optional, Callable
import ipaddress
from scapy.all import ARP, Ether, srp

class NetworkScanner:
    def __init__(self):
        self._is_running = False
        self._threads = []
        self._results = queue.Queue()
        self.common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            8080: "HTTP-Proxy"
        }
        
    def scan_network(self, network_range: str, timeout: int = 5,
                    callback: Optional[Callable[[int, str], None]] = None) -> List[Dict]:
        """
        Scan a network range for active hosts.
        
        Args:
            network_range: Network range in CIDR notation (e.g., '192.168.1.0/24')
            timeout: Timeout in seconds for each host
            callback: Optional callback function to receive progress updates
            
        Returns:
            List of dictionaries containing scan results
        """
        self._is_running = True
        self._threads = []
        self._results = queue.Queue()
        
        try:
            network = ipaddress.ip_network(network_range)
        except ValueError as e:
            return [{"error": f"Invalid network range: {str(e)}"}]
            
        total_hosts = network.num_addresses
        scanned_hosts = 0
        
        # First, perform ARP scan to find live hosts
        live_hosts = self._scan_live_hosts([str(ip) for ip in network.hosts()], timeout)
        
        # Then scan ports for each live host
        for ip in live_hosts:
            if not self._is_running:
                break
                
            thread = threading.Thread(
                target=self._scan_host,
                args=(ip, timeout)
            )
            self._threads.append(thread)
            thread.start()
            
            # Limit number of concurrent threads
            while len(self._threads) >= 100:
                self._threads = [t for t in self._threads if t.is_alive()]
                time.sleep(0.1)
                
            scanned_hosts += 1
            if callback:
                progress = int((scanned_hosts / len(live_hosts)) * 100)
                callback(progress, f"Scanning {ip}...")
                
        # Wait for all threads to complete
        for thread in self._threads:
            thread.join()
            
        # Collect results
        results = []
        while not self._results.empty():
            results.append(self._results.get())
            
        return results
        
    def _scan_live_hosts(self, ip_list: List[str], timeout: float) -> List[str]:
        """Scan for live hosts using ARP requests"""
        live_hosts = []
        arp = ARP(pdst=ip_list)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        
        try:
            result = srp(packet, timeout=timeout, verbose=0)[0]
            for sent, received in result:
                live_hosts.append(received.psrc)
        except Exception:
            pass
            
        return live_hosts
        
    def _scan_host(self, ip: str, timeout: int):
        """
        Scan a single host.
        
        Args:
            ip: IP address to scan
            timeout: Timeout in seconds
        """
        if not self._is_running:
            return
            
        try:
            # Try to get hostname
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = ""
                
            # Scan common ports
            open_ports = []
            for port, service in self.common_ports.items():
                if not self._is_running:
                    break
                    
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    open_ports.append({
                        "port": port,
                        "service": service,
                        "state": "open"
                    })
                    
            status = "up" if open_ports else "down"
            
            result = {
                "ip": ip,
                "hostname": hostname,
                "status": status,
                "open_ports": open_ports
            }
            
            self._results.put(result)
            
        except Exception as e:
            result = {
                "ip": ip,
                "error": str(e)
            }
            self._results.put(result)
            
    def stop(self):
        """Stop the current scan."""
        self._is_running = False 