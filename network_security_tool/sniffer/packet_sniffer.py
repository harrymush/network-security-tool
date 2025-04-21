import threading
import queue
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from typing import Dict, List, Optional, Callable
import time
from datetime import datetime
import sys

class PacketSniffer:
    def __init__(self):
        self.stop_event = threading.Event()
        self.packet_queue = queue.Queue()
        self.interface = None
        self.filter = None
        self.packet_count = 0
        self.start_time = None
        self.sniff_thread = None
        self.is_running = False
        
    def start_sniffing(self, interface: str = None, filter: str = None,
                      packet_callback: Optional[Callable] = None):
        """Start capturing packets on the specified interface"""
        if self.is_running:
            return {"error": "Sniffer is already running"}
            
        self.stop_event.clear()
        self.interface = interface
        self.filter = filter
        self.packet_count = 0
        self.start_time = time.time()
        self.is_running = True
        
        def packet_handler(packet):
            if self.stop_event.is_set():
                return
                
            try:
                self.packet_count += 1
                packet_info = self._analyze_packet(packet)
                
                if packet_callback:
                    packet_callback(packet_info)
            except Exception as e:
                print(f"Error processing packet: {e}", file=sys.stderr)
                
        try:
            # Run sniff in a separate thread to prevent blocking
            self.sniff_thread = threading.Thread(
                target=self._run_sniff,
                args=(interface, filter, packet_handler)
            )
            self.sniff_thread.daemon = True
            self.sniff_thread.start()
            
        except Exception as e:
            self.is_running = False
            error_msg = f"Error starting packet capture: {str(e)}"
            print(error_msg, file=sys.stderr)
            return {"error": error_msg}
            
    def _run_sniff(self, interface, filter, packet_handler):
        """Run the sniff operation in a loop with timeouts"""
        while not self.stop_event.is_set():
            try:
                # Run sniff with a short timeout
                sniff(
                    iface=interface,
                    filter=filter,
                    prn=packet_handler,
                    stop_filter=lambda _: self.stop_event.is_set(),
                    timeout=0.5  # Shorter timeout for more responsive stopping
                )
            except Exception as e:
                if not self.stop_event.is_set():
                    print(f"Error during sniff: {e}", file=sys.stderr)
                    time.sleep(0.1)  # Small delay before retrying
                    
    def _analyze_packet(self, packet) -> Dict:
        """Analyze a captured packet and extract relevant information"""
        packet_info = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
            "protocol": "Unknown",
            "source": "Unknown",
            "destination": "Unknown",
            "length": len(packet),
            "info": ""
        }
        
        try:
            # Ethernet layer
            if Ether in packet:
                packet_info["source_mac"] = packet[Ether].src
                packet_info["dest_mac"] = packet[Ether].dst
                
            # IP layer
            if IP in packet:
                packet_info["source"] = packet[IP].src
                packet_info["destination"] = packet[IP].dst
                packet_info["protocol"] = packet[IP].proto
                
                # TCP
                if TCP in packet:
                    packet_info["protocol"] = "TCP"
                    packet_info["source_port"] = packet[TCP].sport
                    packet_info["dest_port"] = packet[TCP].dport
                    packet_info["info"] = f"Flags: {packet[TCP].flags}"
                    
                # UDP
                elif UDP in packet:
                    packet_info["protocol"] = "UDP"
                    packet_info["source_port"] = packet[UDP].sport
                    packet_info["dest_port"] = packet[UDP].dport
                    
                # ICMP
                elif ICMP in packet:
                    packet_info["protocol"] = "ICMP"
                    packet_info["info"] = f"Type: {packet[ICMP].type}, Code: {packet[ICMP].code}"
                    
            # ARP
            elif ARP in packet:
                packet_info["protocol"] = "ARP"
                packet_info["source"] = packet[ARP].psrc
                packet_info["destination"] = packet[ARP].pdst
                packet_info["info"] = f"Operation: {packet[ARP].op}"
                
        except Exception as e:
            print(f"Error analyzing packet: {e}", file=sys.stderr)
            packet_info["info"] = f"Error: {str(e)}"
            
        return packet_info
        
    def stop_sniffing(self):
        """Stop the packet capture"""
        if not self.is_running:
            return
            
        self.stop_event.set()
        self.is_running = False
        
        if self.sniff_thread and self.sniff_thread.is_alive():
            try:
                self.sniff_thread.join(timeout=1.0)  # Wait for thread to finish with timeout
                if self.sniff_thread.is_alive():
                    print("Warning: Sniff thread did not stop gracefully", file=sys.stderr)
            except Exception as e:
                print(f"Error stopping sniff thread: {e}", file=sys.stderr)
                
        self.sniff_thread = None
        self.stop_event.clear()  # Reset the stop event for next time
            
    def get_statistics(self) -> Dict:
        """Get statistics about the captured packets"""
        if not self.start_time:
            return {}
            
        duration = time.time() - self.start_time
        return {
            "packets_captured": self.packet_count,
            "duration": duration,
            "packets_per_second": self.packet_count / duration if duration > 0 else 0,
            "is_running": self.is_running
        } 