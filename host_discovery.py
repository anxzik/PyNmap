import nmapthon
import datetime

def host_discovery(nm):
    print("Host Discovery Scanner")
    target = input("Enter target IP address range: ")
    
    # Validate target input
    if not target or target.strip() == "":
        print("Error: No target specified!")
        return None
    
    target = target.strip()
    print(f"Scanning target: {target}")
    
    try:
        # Create nmapthon scanner with minimal port scan for host discovery
        # Using a fast scan of one common port instead of -sn to avoid XML parsing issues
        # This will discover hosts even if the port is closed
        print("Creating scanner...")
        scanner = nm.NmapScanner(target, ports='80', arguments='-T4 --max-retries 1')
        
        print("Starting host discovery scan...")
        scanner.run()
        print("Scan completed successfully!")
        
        # Process and display the results
        try:
            scanned_hosts = scanner.scanned_hosts()
            if not scanned_hosts:
                print("No hosts found!")
                return scanner
                
            print(f"\nFound {len(scanned_hosts)} host(s):")
            print("-" * 50)
            
            for host in scanned_hosts:
                print(f"Host: {host}")
                try:
                    print(f"State: {scanner.state(host)}")
                    print(f"Reason: {scanner.reason(host)}")
                    
                    # Get hostnames if available
                    hostnames = scanner.hostnames(host)
                    if hostnames:
                        print(f"Hostnames: {', '.join(hostnames)}")
                    
                    # Show port information for context
                    protocols = scanner.all_protocols(host)
                    for proto in protocols:
                        ports = scanner.scanned_ports(host, proto)
                        for port in ports:
                            port_state, port_reason = scanner.port_state(host, proto, port)
                            print(f"Port {port}/{proto}: {port_state} ({port_reason})")
                        
                except Exception as host_error:
                    print(f"Error getting details for host {host}: {host_error}")
                
                print("-" * 30)
                
        except Exception as results_error:
            print(f"Error processing results: {results_error}")
            # Try to get basic scan info
            try:
                print("Attempting to get basic scan information...")
                print(f"Scan command: {scanner.command}")
                print(f"Scan summary: {scanner.summary}")
            except:
                print("Could not retrieve scan information")
        
        return scanner
        
    except nm.NmapScanError as e:
        error_msg = str(e)
        print(f'Nmapthon scan error: {error_msg}')
        
        # Provide specific guidance for common permission errors
        if "root privileges" in error_msg.lower() or "permission denied" in error_msg.lower():
            print("\n🔧 PERMISSION ERROR SOLUTIONS:")
            print("1. Run with sudo: sudo python __main__.py")
            print("2. Host discovery typically uses ICMP which may require root")
            print("3. Try using -Pn flag to skip host discovery")
        elif "no output" in error_msg.lower():
            print("\n🔧 NO OUTPUT ERROR SOLUTIONS:")
            print("1. Check if the target is reachable: ping", target)
            print("2. Try with different timing settings")
            print("3. Verify network connectivity")
        
        return None
    except Exception as e:
        print(f'Unexpected error: {e}')
        print("\n🔧 GENERAL TROUBLESHOOTING:")
        print("1. Check network connectivity to target")
        print("2. Verify target IP address format")
        print("3. Try with simpler scan options")
        return None


def export_scan_to_dict(scanner):
    """
    Export nmapthon scan results to a structured dictionary format.
    
    Args:
        scanner: nmapthon.NmapScanner object with completed scan results
        
    Returns:
        dict: Structured dictionary containing all scan data
    """
    if not scanner:
        return {"error": "No scanner object provided"}
    
    try:
        # Initialize the main scan data dictionary
        scan_data = {
            "scan_info": {
                "timestamp": datetime.datetime.now().isoformat(),
                "scanner_type": "nmapthon",
                "scan_status": "completed"
            },
            "hosts": {},
            "summary": {
                "total_hosts": 0,
                "hosts_up": 0,
                "hosts_down": 0
            }
        }
        
        # Try to get basic scan information
        try:
            if hasattr(scanner, 'command'):
                scan_data["scan_info"]["command"] = scanner.command
            if hasattr(scanner, 'summary'):
                scan_data["scan_info"]["nmap_summary"] = scanner.summary
        except Exception as e:
            scan_data["scan_info"]["command_error"] = str(e)
        
        # Get all scanned hosts
        try:
            scanned_hosts = scanner.scanned_hosts()
            scan_data["summary"]["total_hosts"] = len(scanned_hosts)
            
            for host in scanned_hosts:
                host_data = {
                    "ip_address": host,
                    "state": "unknown",
                    "reason": "unknown",
                    "hostnames": [],
                    "ports": {},
                    "protocols": [],
                    "scan_time": datetime.datetime.now().isoformat()
                }
                
                try:
                    # Get host state and reason
                    host_state = scanner.state(host)
                    host_data["state"] = host_state
                    
                    if host_state == "up":
                        scan_data["summary"]["hosts_up"] += 1
                    else:
                        scan_data["summary"]["hosts_down"] += 1
                    
                    host_data["reason"] = scanner.reason(host)
                    
                    # Get hostnames
                    hostnames = scanner.hostnames(host)
                    if hostnames:
                        host_data["hostnames"] = list(hostnames)
                    
                    # Get protocol and port information
                    protocols = scanner.all_protocols(host)
                    host_data["protocols"] = list(protocols)
                    
                    for proto in protocols:
                        if proto not in host_data["ports"]:
                            host_data["ports"][proto] = {}
                        
                        ports = scanner.scanned_ports(host, proto)
                        for port in ports:
                            try:
                                port_state, port_reason = scanner.port_state(host, proto, port)
                                host_data["ports"][proto][str(port)] = {
                                    "state": port_state,
                                    "reason": port_reason
                                }
                            except Exception as port_error:
                                host_data["ports"][proto][str(port)] = {
                                    "state": "error",
                                    "reason": str(port_error)
                                }
                    
                except Exception as host_error:
                    host_data["error"] = str(host_error)
                    scan_data["summary"]["hosts_down"] += 1
                
                # Add host data to the main dictionary
                scan_data["hosts"][host] = host_data
                
        except Exception as scan_error:
            scan_data["scan_info"]["scan_error"] = str(scan_error)
            scan_data["scan_info"]["scan_status"] = "error"
        
        return scan_data
        
    except Exception as e:
        return {
            "error": f"Failed to export scan data: {str(e)}",
            "timestamp": datetime.datetime.now().isoformat()
        }


def export_scan_to_json(scanner, filename=None):
    """
    Export nmapthon scan results to a JSON file.
    
    Args:
        scanner: nmapthon.NmapScanner object with completed scan results
        filename: Optional filename for the JSON export (default: auto-generated)
        
    Returns:
        str: Path to the exported JSON file
    """
    import json
    import os
    
    # Get scan data as dictionary
    scan_dict = export_scan_to_dict(scanner)
    
    # Generate filename if not provided
    if not filename:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"nmap_scan_{timestamp}.json"
    
    # Ensure .json extension
    if not filename.endswith('.json'):
        filename += '.json'
    
    try:
        # Write to JSON file
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(scan_dict, f, indent=2, ensure_ascii=False)
        
        print(f"Scan results exported to: {os.path.abspath(filename)}")
        return os.path.abspath(filename)
        
    except Exception as e:
        print(f"Error exporting to JSON: {e}")
        return None


def print_scan_summary(scan_dict):
    """
    Print a formatted summary of the scan results from the dictionary.
    
    Args:
        scan_dict: Dictionary containing scan results from export_scan_to_dict()
    """
    if "error" in scan_dict:
        print(f"Error in scan data: {scan_dict['error']}")
        return
    
    print("\n" + "="*60)
    print("SCAN SUMMARY")
    print("="*60)
    
    # Print scan info
    scan_info = scan_dict.get("scan_info", {})
    print(f"Timestamp: {scan_info.get('timestamp', 'Unknown')}")
    print(f"Status: {scan_info.get('scan_status', 'Unknown')}")
    if "command" in scan_info:
        print(f"Command: {scan_info['command']}")
    
    # Print summary statistics
    summary = scan_dict.get("summary", {})
    print(f"\nHosts Summary:")
    print(f"  Total hosts: {summary.get('total_hosts', 0)}")
    print(f"  Hosts up: {summary.get('hosts_up', 0)}")
    print(f"  Hosts down: {summary.get('hosts_down', 0)}")
    
    # Print detailed host information
    hosts = scan_dict.get("hosts", {})
    if hosts:
        print(f"\nDetailed Host Information:")
        print("-" * 40)
        
        for ip, host_data in hosts.items():
            print(f"\nHost: {ip}")
            print(f"  State: {host_data.get('state', 'unknown')}")
            print(f"  Reason: {host_data.get('reason', 'unknown')}")
            
            hostnames = host_data.get("hostnames", [])
            if hostnames:
                print(f"  Hostnames: {', '.join(hostnames)}")
            
            ports = host_data.get("ports", {})
            for proto, port_dict in ports.items():
                for port_num, port_info in port_dict.items():
                    state = port_info.get("state", "unknown")
                    reason = port_info.get("reason", "unknown")
                    print(f"  Port {port_num}/{proto}: {state} ({reason})")
    
    print("="*60)
