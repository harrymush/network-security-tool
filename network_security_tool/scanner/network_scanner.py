import socket
import threading
import queue
import time
from typing import List, Dict, Tuple, Optional
import concurrent.futures
from scapy.all import ARP, Ether, srp
import ipaddress

class NetworkScanner:
    def __init__(self):
        self.stop_event = threading.Event()
        self.progress_queue = queue.Queue()
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
        
    def scan_network(self, network: str, timeout: float = 1.0,
                    max_threads: int = 100,
                    progress_callback: Optional[callable] = None) -> List[Dict]:
        """Scan a network for live hosts and open ports"""
        self.stop_event.clear()
        results = []
        
        # Get all IPs in the network
        try:
            network = ipaddress.ip_network(network)
            ip_list = [str(ip) for ip in network.hosts()]
        except ValueError:
            return [{"error": "Invalid network address"}]
            
        # Scan for live hosts
        live_hosts = self._scan_live_hosts(ip_list, timeout)
        
        # Scan ports for each live host
        for host in live_hosts:
            if self.stop_event.is_set():
                break
                
            open_ports = self._scan_ports(host, timeout, max_threads)
            if open_ports:
                results.append({
                    "ip": host,
                    "ports": open_ports
                })
                
            if progress_callback:
                progress = (len(results) / len(live_hosts)) * 100
                progress_callback(progress)
                
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
        
    def _scan_ports(self, host: str, timeout: float,
                   max_threads: int) -> List[Dict]:
        """Scan ports for a specific host"""
        open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_port = {
                executor.submit(self._check_port, host, port, timeout): port
                for port in self.common_ports.keys()
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                if self.stop_event.is_set():
                    break
                    
                port = future_to_port[future]
                try:
                    is_open, service = future.result()
                    if is_open:
                        open_ports.append({
                            "port": port,
                            "service": service,
                            "state": "open"
                        })
                except Exception:
                    pass
                    
        return open_ports
        
    def _check_port(self, host: str, port: int,
                   timeout: float) -> Tuple[bool, str]:
        """Check if a port is open and identify the service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                return True, self.common_ports.get(port, "Unknown")
            return False, ""
        except:
            return False, ""
            
    def stop_scan(self):
        """Stop the current scan operation"""
        self.stop_event.set() 