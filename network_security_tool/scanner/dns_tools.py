import dns.resolver
import dns.reversename
import socket
from typing import Dict, List, Optional, Callable

class DNSTools:
    def __init__(self):
        self._is_running = False
        
    def query_dns(self, domain: str, record_type: str = "A",
                 callback: Optional[Callable[[str], None]] = None) -> List[Dict]:
        """
        Query DNS records for a domain.
        
        Args:
            domain: Domain name to query
            record_type: Type of DNS record (A, AAAA, CNAME, MX, NS, TXT)
            callback: Optional callback function to receive results in real-time
            
        Returns:
            List of dictionaries containing DNS query results
        """
        self._is_running = True
        results = []
        
        try:
            # Resolve domain
            if callback:
                callback(f"Querying {record_type} records for {domain}...")
                
            answers = dns.resolver.resolve(domain, record_type)
            
            for answer in answers:
                result = {
                    "type": record_type,
                    "domain": domain,
                    "value": str(answer)
                }
                
                # Add additional info based on record type
                if record_type == "MX":
                    result["priority"] = answer.preference
                elif record_type == "TXT":
                    result["value"] = answer.strings[0].decode()
                    
                results.append(result)
                
            if callback:
                callback(f"Found {len(results)} {record_type} records")
                
        except dns.resolver.NXDOMAIN:
            result = {
                "error": f"Domain {domain} does not exist"
            }
            results.append(result)
            if callback:
                callback(f"Error: Domain {domain} does not exist")
                
        except dns.resolver.NoAnswer:
            result = {
                "error": f"No {record_type} records found for {domain}"
            }
            results.append(result)
            if callback:
                callback(f"Error: No {record_type} records found")
                
        except Exception as e:
            result = {
                "error": f"DNS query failed: {str(e)}"
            }
            results.append(result)
            if callback:
                callback(f"Error: {str(e)}")
                
        return results
        
    def reverse_dns(self, ip: str,
                   callback: Optional[Callable[[str], None]] = None) -> List[Dict]:
        """
        Perform reverse DNS lookup.
        
        Args:
            ip: IP address to look up
            callback: Optional callback function to receive results in real-time
            
        Returns:
            List of dictionaries containing reverse DNS results
        """
        self._is_running = True
        results = []
        
        try:
            if callback:
                callback(f"Performing reverse DNS lookup for {ip}...")
                
            # Convert IP to reverse DNS format
            rev_name = dns.reversename.from_address(ip)
            
            # Query PTR record
            answers = dns.resolver.resolve(rev_name, "PTR")
            
            for answer in answers:
                result = {
                    "type": "PTR",
                    "ip": ip,
                    "hostname": str(answer)
                }
                results.append(result)
                
            if callback:
                callback(f"Found {len(results)} PTR records")
                
        except dns.resolver.NXDOMAIN:
            result = {
                "error": f"No PTR records found for {ip}"
            }
            results.append(result)
            if callback:
                callback(f"Error: No PTR records found")
                
        except Exception as e:
            result = {
                "error": f"Reverse DNS lookup failed: {str(e)}"
            }
            results.append(result)
            if callback:
                callback(f"Error: {str(e)}")
                
        return results
        
    def get_dns_servers(self, domain: str,
                       callback: Optional[Callable[[str], None]] = None) -> List[Dict]:
        """
        Get DNS servers for a domain.
        
        Args:
            domain: Domain name to query
            callback: Optional callback function to receive results in real-time
            
        Returns:
            List of dictionaries containing DNS server information
        """
        self._is_running = True
        results = []
        
        try:
            if callback:
                callback(f"Getting DNS servers for {domain}...")
                
            # Query NS records
            answers = dns.resolver.resolve(domain, "NS")
            
            for answer in answers:
                ns_domain = str(answer)
                
                # Get A records for NS domain
                try:
                    a_records = dns.resolver.resolve(ns_domain, "A")
                    for a_record in a_records:
                        result = {
                            "type": "NS",
                            "domain": domain,
                            "nameserver": ns_domain,
                            "ip": str(a_record)
                        }
                        results.append(result)
                except:
                    result = {
                        "type": "NS",
                        "domain": domain,
                        "nameserver": ns_domain,
                        "ip": "unknown"
                    }
                    results.append(result)
                    
            if callback:
                callback(f"Found {len(results)} DNS servers")
                
        except Exception as e:
            result = {
                "error": f"Failed to get DNS servers: {str(e)}"
            }
            results.append(result)
            if callback:
                callback(f"Error: {str(e)}")
                
        return results
        
    def stop(self):
        """Stop the current operation."""
        self._is_running = False 