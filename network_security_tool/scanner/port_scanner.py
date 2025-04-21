import socket
import threading
import queue
import time
from typing import Dict, List, Optional, Callable

class PortScanner:
    def __init__(self):
        self._is_running = False
        self._threads = []
        self._queue = queue.Queue()
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
        
    def scan_ports(self, target: str, start_port: int, end_port: int, callback=None):
        """Scan a range of ports on a target."""
        self._is_running = True
        self._threads = []
        self._queue = queue.Queue()
        
        # Create threads for scanning
        for port in range(start_port, end_port + 1):
            if not self._is_running:
                break
                
            thread = threading.Thread(
                target=self._scan_port,
                args=(target, port, callback)
            )
            thread.daemon = True
            thread.start()
            self._threads.append(thread)
            
        # Wait for all threads to complete
        for thread in self._threads:
            thread.join()
            
    def _scan_port(self, target: str, port: int, callback=None):
        """Scan a single port."""
        try:
            # Create a socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            # Try to connect
            result = sock.connect_ex((target, port))
            
            if result == 0:
                # Port is open
                service = socket.getservbyport(port, 'tcp')
                result_dict = {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "protocol": "TCP"  # Fixed: Using string instead of function
                }
                
                if callback:
                    callback(result_dict)
                    
            sock.close()
            
        except Exception as e:
            if callback:
                callback({
                    "port": port,
                    "state": "error",
                    "error": str(e),
                    "protocol": "TCP"  # Fixed: Using string instead of function
                })
                
    def stop(self):
        """Stop the port scan."""
        self._is_running = False 