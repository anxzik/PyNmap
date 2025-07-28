import json
import datetime
import os
from typing import Dict, List, Any, Optional, Union

class ScanResultsManager:
    """
    Manages scan results from both host discovery and port scanning operations.
    Provides functionality to import, store, export, and analyze scan data.
    """
    
    def __init__(self):
        self.scan_history: List[Dict[str, Any]] = []
        self.current_scan: Optional[Dict[str, Any]] = None
        
    def import_host_discovery_results(self, scanner) -> Dict[str, Any]:
        """
        Import results from a host discovery scan.
        
        Args:
            scanner: nmapthon.NmapScanner object with completed scan results
            
        Returns:
            dict: Structured dictionary containing host discovery data
        """
        from host_discovery import export_scan_to_dict
        
        scan_data = export_scan_to_dict(scanner)
        if scan_data and "error" not in scan_data:
            scan_data["scan_info"]["scan_category"] = "host_discovery"
            self.current_scan = scan_data
            self.scan_history.append(scan_data)
            
        return scan_data
    
    def import_port_scan_results(self, scanner) -> Dict[str, Any]:
        """
        Import results from a port scan.
        
        Args:
            scanner: nmapthon.NmapScanner object with completed scan results
            
        Returns:
            dict: Structured dictionary containing port scan data
        """
        from port_scanner import export_port_scan_to_dict
        
        scan_data = export_port_scan_to_dict(scanner)
        if scan_data and "error" not in scan_data:
            scan_data["scan_info"]["scan_category"] = "port_scan"
            self.current_scan = scan_data
            self.scan_history.append(scan_data)
            
        return scan_data
    
    def get_all_discovered_hosts(self) -> List[Dict[str, Any]]:
        """
        Get all unique hosts discovered across all scans.
        
        Returns:
            list: List of host dictionaries with combined information
        """
        hosts_dict = {}
        
        for scan in self.scan_history:
            if "hosts" in scan:
                for ip, host_data in scan["hosts"].items():
                    if ip not in hosts_dict:
                        hosts_dict[ip] = {
                            "ip_address": ip,
                            "first_seen": host_data.get("scan_time", "unknown"),
                            "last_seen": host_data.get("scan_time", "unknown"),
                            "scan_count": 1,
                            "states": [host_data.get("state", "unknown")],
                            "hostnames": set(host_data.get("hostnames", [])),
                            "open_ports": {},
                            "os_info": {},
                            "scan_types": [scan.get("scan_info", {}).get("scan_category", "unknown")]
                        }
                    else:
                        # Update existing host information
                        hosts_dict[ip]["last_seen"] = host_data.get("scan_time", "unknown")
                        hosts_dict[ip]["scan_count"] += 1
                        hosts_dict[ip]["states"].append(host_data.get("state", "unknown"))
                        hosts_dict[ip]["hostnames"].update(host_data.get("hostnames", []))
                        
                        scan_type = scan.get("scan_info", {}).get("scan_category", "unknown")
                        if scan_type not in hosts_dict[ip]["scan_types"]:
                            hosts_dict[ip]["scan_types"].append(scan_type)
                    
                    # Add port information if available
                    if "ports" in host_data:
                        for proto, ports in host_data["ports"].items():
                            if proto not in hosts_dict[ip]["open_ports"]:
                                hosts_dict[ip]["open_ports"][proto] = {}
                            
                            for port_num, port_info in ports.items():
                                if port_info.get("state") == "open":
                                    hosts_dict[ip]["open_ports"][proto][port_num] = port_info
                    
                    # Update OS information
                    if "os_info" in host_data and host_data["os_info"]:
                        hosts_dict[ip]["os_info"].update(host_data["os_info"])
        
        # Convert sets to lists for JSON serialization
        for host in hosts_dict.values():
            host["hostnames"] = list(host["hostnames"])
        
        return list(hosts_dict.values())
    
    def get_open_ports_summary(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get a summary of all open ports found across all scans.
        
        Returns:
            dict: Dictionary with port numbers as keys and host lists as values
        """
        ports_summary = {}
        
        for scan in self.scan_history:
            if "hosts" in scan:
                for ip, host_data in scan["hosts"].items():
                    if "ports" in host_data:
                        for proto, ports in host_data["ports"].items():
                            for port_num, port_info in ports.items():
                                if port_info.get("state") == "open":
                                    port_key = f"{port_num}/{proto}"
                                    
                                    if port_key not in ports_summary:
                                        ports_summary[port_key] = []
                                    
                                    # Check if this host is already in the list for this port
                                    host_exists = any(h["ip"] == ip for h in ports_summary[port_key])
                                    
                                    if not host_exists:
                                        host_entry = {
                                            "ip": ip,
                                            "hostnames": host_data.get("hostnames", []),
                                            "service": port_info.get("service", {}),
                                            "scan_time": host_data.get("scan_time", "unknown")
                                        }
                                        ports_summary[port_key].append(host_entry)
        
        return ports_summary
    
    def get_scan_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive statistics about all scans.
        
        Returns:
            dict: Statistics dictionary
        """
        stats = {
            "total_scans": len(self.scan_history),
            "scan_types": {},
            "total_unique_hosts": 0,
            "hosts_up": 0,
            "hosts_down": 0,
            "total_open_ports": 0,
            "unique_services": set(),
            "scan_timerange": {
                "first_scan": None,
                "last_scan": None
            }
        }
        
        all_hosts = self.get_all_discovered_hosts()
        stats["total_unique_hosts"] = len(all_hosts)
        
        for host in all_hosts:
            if "up" in host["states"]:
                stats["hosts_up"] += 1
            else:
                stats["hosts_down"] += 1
            
            # Count open ports
            for proto, ports in host["open_ports"].items():
                stats["total_open_ports"] += len(ports)
                
                # Collect unique services
                for port_info in ports.values():
                    service = port_info.get("service", {})
                    if service.get("name"):
                        stats["unique_services"].add(service["name"])
        
        # Convert set to list for JSON serialization
        stats["unique_services"] = list(stats["unique_services"])
        
        # Scan type statistics
        for scan in self.scan_history:
            scan_type = scan.get("scan_info", {}).get("scan_category", "unknown")
            stats["scan_types"][scan_type] = stats["scan_types"].get(scan_type, 0) + 1
            
            # Update time range
            timestamp = scan.get("scan_info", {}).get("timestamp")
            if timestamp:
                if not stats["scan_timerange"]["first_scan"] or timestamp < stats["scan_timerange"]["first_scan"]:
                    stats["scan_timerange"]["first_scan"] = timestamp
                if not stats["scan_timerange"]["last_scan"] or timestamp > stats["scan_timerange"]["last_scan"]:
                    stats["scan_timerange"]["last_scan"] = timestamp
        
        return stats
    
    def export_to_json(self, filename: Optional[str] = None, include_history: bool = True) -> str:
        """
        Export scan results to JSON file.
        
        Args:
            filename: Optional filename for export
            include_history: Whether to include full scan history
            
        Returns:
            str: Path to exported file
        """
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_results_{timestamp}.json"
        
        if not filename.endswith('.json'):
            filename += '.json'
        
        export_data = {
            "export_info": {
                "timestamp": datetime.datetime.now().isoformat(),
                "export_type": "comprehensive_scan_results"
            },
            "statistics": self.get_scan_statistics(),
            "discovered_hosts": self.get_all_discovered_hosts(),
            "open_ports_summary": self.get_open_ports_summary()
        }
        
        if include_history:
            export_data["scan_history"] = self.scan_history
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            print(f"Scan results exported to: {os.path.abspath(filename)}")
            return os.path.abspath(filename)
            
        except Exception as e:
            print(f"Error exporting to JSON: {e}")
            return None
    
    def export_to_csv(self, filename: Optional[str] = None) -> str:
        """
        Export discovered hosts to CSV format.
        
        Args:
            filename: Optional filename for export
            
        Returns:
            str: Path to exported file
        """
        import csv
        
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"discovered_hosts_{timestamp}.csv"
        
        if not filename.endswith('.csv'):
            filename += '.csv'
        
        try:
            hosts = self.get_all_discovered_hosts()
            
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                if not hosts:
                    f.write("No hosts discovered\n")
                    return os.path.abspath(filename)
                
                fieldnames = [
                    'ip_address', 'hostnames', 'first_seen', 'last_seen', 
                    'scan_count', 'states', 'open_ports_count', 'scan_types'
                ]
                
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                for host in hosts:
                    # Count open ports
                    open_ports_count = sum(len(ports) for ports in host["open_ports"].values())
                    
                    row = {
                        'ip_address': host['ip_address'],
                        'hostnames': ', '.join(host['hostnames']),
                        'first_seen': host['first_seen'],
                        'last_seen': host['last_seen'],
                        'scan_count': host['scan_count'],
                        'states': ', '.join(set(host['states'])),
                        'open_ports_count': open_ports_count,
                        'scan_types': ', '.join(host['scan_types'])
                    }
                    writer.writerow(row)
            
            print(f"Host data exported to CSV: {os.path.abspath(filename)}")
            return os.path.abspath(filename)
            
        except Exception as e:
            print(f"Error exporting to CSV: {e}")
            return None
    
    def print_comprehensive_summary(self):
        """
        Print a comprehensive summary of all scan results.
        """
        print("\n" + "="*80)
        print("COMPREHENSIVE SCAN RESULTS SUMMARY")
        print("="*80)
        
        stats = self.get_scan_statistics()
        
        # Print statistics
        print(f"Total Scans Performed: {stats['total_scans']}")
        print(f"Scan Types:")
        for scan_type, count in stats['scan_types'].items():
            print(f"  {scan_type}: {count}")
        
        print(f"\nHost Summary:")
        print(f"  Total Unique Hosts: {stats['total_unique_hosts']}")
        print(f"  Hosts Up: {stats['hosts_up']}")
        print(f"  Hosts Down: {stats['hosts_down']}")
        print(f"  Total Open Ports: {stats['total_open_ports']}")
        print(f"  Unique Services: {len(stats['unique_services'])}")
        
        if stats['scan_timerange']['first_scan']:
            print(f"\nTime Range:")
            print(f"  First Scan: {stats['scan_timerange']['first_scan']}")
            print(f"  Last Scan: {stats['scan_timerange']['last_scan']}")
        
        # Print discovered hosts
        hosts = self.get_all_discovered_hosts()
        if hosts:
            print(f"\nDiscovered Hosts ({len(hosts)}):")
            print("-" * 60)
            
            for host in hosts:
                print(f"\nHost: {host['ip_address']}")
                if host['hostnames']:
                    print(f"  Hostnames: {', '.join(host['hostnames'])}")
                print(f"  States: {', '.join(set(host['states']))}")
                print(f"  Scan Count: {host['scan_count']}")
                print(f"  Scan Types: {', '.join(host['scan_types'])}")
                
                # Show open ports
                total_open = sum(len(ports) for ports in host["open_ports"].values())
                if total_open > 0:
                    print(f"  Open Ports ({total_open}):")
                    for proto, ports in host["open_ports"].items():
                        for port_num, port_info in ports.items():
                            service = port_info.get("service", {})
                            port_display = f"{port_num}/{proto}"
                            if service.get("name"):
                                port_display += f" ({service['name']}"
                                if service.get("version"):
                                    port_display += f" {service['version']}"
                                port_display += ")"
                            print(f"    {port_display}")
        
        # Print open ports summary
        ports_summary = self.get_open_ports_summary()
        if ports_summary:
            print(f"\nOpen Ports Summary:")
            print("-" * 40)
            
            for port, hosts_list in sorted(ports_summary.items()):
                print(f"\nPort {port} ({len(hosts_list)} hosts):")
                for host_info in hosts_list:
                    service = host_info.get("service", {})
                    service_name = service.get("name", "unknown")
                    print(f"  {host_info['ip']} ({service_name})")
        
        print("="*80)
    
    def clear_history(self):
        """Clear all scan history."""
        self.scan_history.clear()
        self.current_scan = None
        print("Scan history cleared.")
    
    def load_from_json(self, filename: str) -> bool:
        """
        Load scan results from a JSON file.
        
        Args:
            filename: Path to JSON file
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if "scan_history" in data:
                self.scan_history.extend(data["scan_history"])
                if self.scan_history:
                    self.current_scan = self.scan_history[-1]
                print(f"Loaded {len(data['scan_history'])} scans from {filename}")
                return True
            else:
                print("No scan history found in the file.")
                return False
                
        except Exception as e:
            print(f"Error loading from JSON: {e}")
            return False


# Global instance for easy access
scan_results = ScanResultsManager()


def process_scan_results(scanner, scan_type: str = "auto") -> Dict[str, Any]:
    """
    Process scan results and add them to the global results manager.
    
    Args:
        scanner: nmapthon.NmapScanner object with completed scan results
        scan_type: Type of scan ("host_discovery", "port_scan", or "auto")
        
    Returns:
        dict: Processed scan data
    """
    if not scanner:
        return {"error": "No scanner object provided"}
    
    if scan_type == "auto":
        # Try to determine scan type based on scanner properties
        try:
            # Check if we have port information
            hosts = scanner.scanned_hosts()
            if hosts:
                for host in hosts:
                    protocols = scanner.all_protocols(host)
                    if protocols:
                        ports = scanner.scanned_ports(host, protocols[0])
                        if len(ports) > 1:  # More than one port suggests port scan
                            scan_type = "port_scan"
                            break
                else:
                    scan_type = "host_discovery"
            else:
                scan_type = "host_discovery"
        except:
            scan_type = "host_discovery"
    
    if scan_type == "port_scan":
        return scan_results.import_port_scan_results(scanner)
    else:
        return scan_results.import_host_discovery_results(scanner)


def export_current_results(format_type: str = "json", filename: Optional[str] = None) -> Optional[str]:
    """
    Export current scan results in the specified format.
    
    Args:
        format_type: Export format ("json" or "csv")
        filename: Optional filename
        
    Returns:
        str: Path to exported file, or None if failed
    """
    if format_type.lower() == "csv":
        return scan_results.export_to_csv(filename)
    else:
        return scan_results.export_to_json(filename)


def print_results_summary():
    """Print a summary of all scan results."""
    scan_results.print_comprehensive_summary()


def get_discovered_hosts() -> List[Dict[str, Any]]:
    """Get all discovered hosts."""
    return scan_results.get_all_discovered_hosts()


def get_open_ports_summary() -> Dict[str, List[Dict[str, Any]]]:
    """Get summary of open ports."""
    return scan_results.get_open_ports_summary()


def clear_all_results():
    """Clear all scan results."""
    scan_results.clear_history()


def load_results_from_file(filename: str) -> bool:
    """Load results from a JSON file."""
    return scan_results.load_from_json(filename)