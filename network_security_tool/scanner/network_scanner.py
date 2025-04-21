import socket
import threading
import queue
import time
import subprocess
from typing import List, Dict, Optional, Callable
import ipaddress
import logging
import platform
import os

class NetworkScanner:
    def __init__(self):
        self._is_running = False
        self._threads = []
        self._results = queue.Queue()
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)  # Change to INFO level
        
        # Add console handler for important messages only
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter('%(message)s')  # Simplified format
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)
        
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
        
        self._stop_event = threading.Event()
        
    def scan_network(self, network_range: str, timeout: int = 5,
                    progress_callback: Optional[Callable[[int, str], None]] = None,
                    quick_scan: bool = False,
                    result_callback: Optional[Callable[[Dict], None]] = None) -> List[Dict]:
        """Scan a network range for active hosts and open ports."""
        self.logger.info(f"Starting network scan for range: {network_range}")
        self._is_running = True
        self._threads = []
        self._results = queue.Queue()
        
        try:
            network = ipaddress.ip_network(network_range)
            total_hosts = network.num_addresses
            scanned_hosts = 0
            
            # Create thread pool
            thread_pool = []
            results_queue = queue.Queue()
            
            # Scan each host
            for ip in network.hosts():
                if self._stop_event.is_set():
                    break
                    
                # Create and start thread
                thread = threading.Thread(
                    target=self._scan_host,
                    args=(str(ip), timeout, results_queue, quick_scan)
                )
                thread.daemon = True
                thread.start()
                thread_pool.append(thread)
                
                # Limit concurrent threads
                if len(thread_pool) >= 20:
                    for t in thread_pool:
                        t.join(timeout=1)
                    thread_pool = [t for t in thread_pool if t.is_alive()]
                    
                # Update progress
                scanned_hosts += 1
                if progress_callback:
                    progress = int((scanned_hosts / total_hosts) * 100)
                    progress_callback(progress, f"Scanning {ip}...")
                    
                # Process results as they come in
                while not results_queue.empty():
                    result = results_queue.get()
                    if result_callback:
                        result_callback(result)
                        
            # Wait for remaining threads
            for thread in thread_pool:
                thread.join(timeout=1)
                
            # Get any remaining results
            results = []
            while not results_queue.empty():
                result = results_queue.get()
                results.append(result)
                if result_callback:
                    result_callback(result)
                    
            self.logger.info(f"Scan complete. Found {len(results)} results")
            return results
            
        except Exception as e:
            self.logger.error(f"Network scan error: {str(e)}")
            if progress_callback:
                progress_callback(0, f"Error: {str(e)}")
            return []
            
    def _scan_host(self, ip: str, timeout: int, results_queue: queue.Queue, quick_scan: bool = False):
        """Scan a single host for open ports."""
        if not self._is_running:
            return
            
        try:
            # Check if host is up
            is_up = self._ping_host(ip, timeout)
            
            if not is_up:
                results_queue.put({
                    'ip': ip,
                    'status': 'down',
                    'hostname': '',
                    'open_ports': []
                })
                return
                
            # Get hostname
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except (socket.herror, socket.gaierror):
                hostname = ''
                
            if quick_scan:
                # Only return host info without port scan
                results_queue.put({
                    'ip': ip,
                    'status': 'up',
                    'hostname': hostname,
                    'open_ports': []
                })
                return
                
            # Scan ports
            open_ports = []
            for port in range(1, 1025):  # Scan common ports
                if self._stop_event.is_set():
                    break
                    
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append({
                            'port': port,
                            'service': self._get_service_name(port)
                        })
                    sock.close()
                except Exception:
                    continue
                    
            results_queue.put({
                'ip': ip,
                'status': 'up',
                'hostname': hostname,
                'open_ports': open_ports
            })
            
        except Exception as e:
            results_queue.put({
                'ip': ip,
                'status': 'error',
                'error': str(e)
            })
            
    def _ping_host(self, ip: str, timeout: float) -> bool:
        """Ping a host to check if it's up."""
        try:
            # Use appropriate ping command based on OS
            if platform.system().lower() == "windows":
                ping_cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000))]
            else:
                ping_cmd = ["ping", "-c", "1", "-W", str(timeout)]
            
            process = subprocess.Popen(
                ping_cmd + [ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = process.communicate(timeout=timeout)
            
            return process.returncode == 0
                
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            return False
            
    def _get_service_name(self, port: int) -> str:
        """Get service name for a given port"""
        return self.common_ports.get(port, "Unknown")
        
    def stop(self):
        """Stop the current scan."""
        self.logger.info("Stopping scan...")
        self._is_running = False
        self._stop_event.set()
        for thread in self._threads:
            if thread.is_alive():
                thread.join(timeout=1)  # Wait up to 1 second for threads to finish 