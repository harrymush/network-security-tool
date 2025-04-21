import threading
import queue
import time
import logging
from scapy.all import sniff, conf, get_if_list
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
import netifaces

logger = logging.getLogger(__name__)

class PacketSniffer:
    def __init__(self):
        self.sniffer = None
        self.running = False
        self.packet_queue = queue.Queue()
        self.start_time = None
        self.packet_count = 0

    def get_interfaces(self):
        """Get list of available network interfaces."""
        try:
            # Get interfaces using both methods
            scapy_interfaces = get_if_list()
            netifaces_interfaces = netifaces.interfaces()
            
            # Use the intersection of both lists to ensure reliability
            interfaces = list(set(scapy_interfaces) & set(netifaces_interfaces))
            return interfaces
        except Exception as e:
            logger.error(f"Error getting interfaces: {str(e)}")
            return []

    def start_sniffing(self, interface, filter_text=None, callback=None):
        """Start sniffing packets on the specified interface."""
        try:
            logger.debug(f"Starting sniffing on interface {interface} with filter {filter_text}")
            
            # Configure Scapy to use the specified interface
            conf.iface = interface
            
            # Start the sniffer in a separate thread
            self.running = True
            self.start_time = time.time()
            self.packet_count = 0
            
            def packet_handler(packet):
                if not self.running:
                    return
                    
                try:
                    packet_info = self._analyze_packet(packet)
                    self.packet_count += 1
                    
                    if callback:
                        callback(packet_info)
                    else:
                        self.packet_queue.put(packet_info)
                        
                except Exception as e:
                    logger.error(f"Error analyzing packet: {str(e)}")
            
            self.sniffer = sniff(
                iface=interface,
                filter=filter_text,
                prn=packet_handler,
                store=0,
                stop_filter=lambda _: not self.running
            )
            
        except Exception as e:
            logger.error(f"Error starting sniffer: {str(e)}")
            raise

    def _analyze_packet(self, packet):
        """Analyze a packet and extract relevant information."""
        packet_info = {
            'time': time.strftime('%H:%M:%S', time.localtime()),
            'source': '',
            'destination': '',
            'protocol': '',
            'length': len(packet)
        }
        
        try:
            # Get Ethernet layer info
            if Ether in packet:
                eth = packet[Ether]
                packet_info['source_mac'] = eth.src
                packet_info['dest_mac'] = eth.dst
            
            # Get IP layer info
            if IP in packet:
                ip = packet[IP]
                packet_info['source'] = ip.src
                packet_info['destination'] = ip.dst
                
                # Get transport layer protocol
                if TCP in packet:
                    packet_info['protocol'] = 'TCP'
                    packet_info['source_port'] = packet[TCP].sport
                    packet_info['dest_port'] = packet[TCP].dport
                elif UDP in packet:
                    packet_info['protocol'] = 'UDP'
                    packet_info['source_port'] = packet[UDP].sport
                    packet_info['dest_port'] = packet[UDP].dport
                elif ICMP in packet:
                    packet_info['protocol'] = 'ICMP'
                else:
                    packet_info['protocol'] = 'IP'
            else:
                packet_info['protocol'] = 'Ethernet'
                
        except Exception as e:
            logger.error(f"Error analyzing packet: {str(e)}")
            packet_info['protocol'] = 'Unknown'
            
        return packet_info

    def stop_sniffing(self):
        """Stop the packet sniffer."""
        logger.debug("Stopping sniffer")
        self.running = False
        if self.sniffer:
            self.sniffer.stop()

    def get_statistics(self):
        """Get statistics about the captured packets."""
        if not self.start_time:
            return {'packets': 0, 'duration': 0, 'packets_per_second': 0}
            
        duration = time.time() - self.start_time
        return {
            'packets': self.packet_count,
            'duration': duration,
            'packets_per_second': self.packet_count / duration if duration > 0 else 0
        } 