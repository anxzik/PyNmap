import nmapthon
import datetime
import re

def port_scanner(nm):
    """
    Interactive port scanner with various scanning options and port selection.
    
    Args:
        nm: nmapthon module reference
        
    Returns:
        nmapthon.NmapScanner: Scanner object with results
    """
    print("\n" + "="*60)
    print("PORT SCANNER")
    print("="*60)
    
    # Get target
    target = input("Enter target IP address or range: ").strip()
    if not target:
        print("Error: No target specified!")
        return None
    
    print(f"Target: {target}")
    
    # Display port selection menu
    print("\n--- Port Selection ---")
    print("1. Common ports (top 1000)")
    print("2. All ports (1-65535)")
    print("3. Specific port range")
    print("4. Custom port list")
    print("5. Top 100 ports")
    print("6. Top 10 ports")
    
    port_choice = input("Select port option (1-6): ").strip()
    
    # Configure ports based on selection
    ports = ""
    if port_choice == "1":
        ports = "--top-ports 1000"
    elif port_choice == "2":
        ports = "1-65535"
    elif port_choice == "3":
        start_port = input("Enter start port: ").strip()
        end_port = input("Enter end port: ").strip()
        if start_port.isdigit() and end_port.isdigit():
            ports = f"{start_port}-{end_port}"
        else:
            print("Invalid port range, using top 1000 ports")
            ports = "--top-ports 1000"
    elif port_choice == "4":
        custom_ports = input("Enter comma-separated port list (e.g., 22,80,443): ").strip()
        if custom_ports:
            # Validate port list
            port_list = [p.strip() for p in custom_ports.split(',')]
            valid_ports = []
            for port in port_list:
                if port.isdigit() and 1 <= int(port) <= 65535:
                    valid_ports.append(port)
            if valid_ports:
                ports = ','.join(valid_ports)
            else:
                print("No valid ports found, using top 1000 ports")
                ports = "--top-ports 1000"
        else:
            ports = "--top-ports 1000"
    elif port_choice == "5":
        ports = "--top-ports 100"
    elif port_choice == "6":
        ports = "--top-ports 10"
    else:
        print("Invalid choice, using top 1000 ports")
        ports = "--top-ports 1000"
    
    # Display scan type menu
    print("\n--- Scan Type ---")
    print("1. TCP SYN Scan (fast, requires root)")
    print("2. TCP Connect Scan (reliable, no root required) ⭐ RECOMMENDED")
    print("3. UDP Scan (slower, requires root)")
    print("4. TCP SYN + UDP Scan (comprehensive, requires root)")
    print("5. Aggressive scan (OS detection, version detection, script scanning, requires root)")
    print("6. Stealth scan (slower, less detectable, requires root)")
    
    scan_choice = input("Select scan type (1-6): ").strip()
    
    # Configure scan arguments
    arguments = ["-T4"]  # Default timing
    requires_root = False
    
    if scan_choice == "1":
        arguments.append("-sS")  # SYN scan
        requires_root = True
    elif scan_choice == "2":
        arguments.append("-sT")  # TCP connect scan
    elif scan_choice == "3":
        arguments.append("-sU")  # UDP scan
        arguments.append("-T3")  # Slower timing for UDP
        requires_root = True
    elif scan_choice == "4":
        arguments.append("-sS")
        arguments.append("-sU")
        arguments.append("-T3")  # Slower timing for combined scan
        requires_root = True
    elif scan_choice == "5":
        arguments.extend(["-A", "-sS"])  # Aggressive scan
        requires_root = True
    elif scan_choice == "6":
        arguments.extend(["-sS", "-T2", "-f"])  # Stealth scan
        requires_root = True
    else:
        arguments.append("-sT")  # Default to TCP connect scan (no root required)
    
    # Additional options
    print("\n--- Additional Options ---")
    print("1. Enable OS detection (requires root)")
    print("2. Enable version detection (no root required)")
    print("3. Enable script scanning (no root required)")
    print("4. Skip host discovery (assume host is up)")
    print("5. None")
    
    additional_choice = input("Select additional option (1-5, or press Enter for none): ").strip()
    
    if additional_choice == "1":
        arguments.append("-O")
        requires_root = True  # OS detection requires root
    elif additional_choice == "2":
        arguments.append("-sV")
    elif additional_choice == "3":
        arguments.append("-sC")
    elif additional_choice == "4":
        arguments.append("-Pn")
    
    # Timing options
    print("\n--- Timing Template ---")
    print("1. T0 - Paranoid (very slow)")
    print("2. T1 - Sneaky (slow)")
    print("3. T2 - Polite (slower)")
    print("4. T3 - Normal (default)")
    print("5. T4 - Aggressive (faster)")
    print("6. T5 - Insane (very fast)")
    
    timing_choice = input("Select timing (1-6, or press Enter for T4): ").strip()
    
    # Remove existing timing and set new one
    arguments = [arg for arg in arguments if not arg.startswith("-T")]
    
    if timing_choice == "1":
        arguments.append("-T0")
    elif timing_choice == "2":
        arguments.append("-T1")
    elif timing_choice == "3":
        arguments.append("-T2")
    elif timing_choice == "4":
        arguments.append("-T3")
    elif timing_choice == "5":
        arguments.append("-T4")
    elif timing_choice == "6":
        arguments.append("-T5")
    else:
        arguments.append("-T4")  # Default
    
    # Combine arguments
    final_arguments = " ".join(arguments)
    
    print(f"\nScan Configuration:")
    print(f"Target: {target}")
    print(f"Ports: {ports}")
    print(f"Arguments: {final_arguments}")
    
    # Check for root privileges if required
    if requires_root:
        import os
        if os.geteuid() != 0:
            print(f"\n⚠️  WARNING: This scan configuration requires root privileges!")
            print("The selected options may fail without sudo/root access.")
            print("Consider using:")
            print("- TCP Connect scan (-sT) instead of SYN scan (-sS)")
            print("- Removing OS detection (-O)")
            print("- Running with sudo: sudo python __main__.py")
            
            fallback = input("\nWould you like to automatically switch to TCP Connect scan? (y/N): ").strip().lower()
            if fallback == 'y':
                # Replace problematic arguments with safe alternatives
                safe_arguments = []
                for arg in arguments:
                    if arg == "-sS":
                        safe_arguments.append("-sT")
                    elif arg == "-sU":
                        continue  # Skip UDP scan
                    elif arg == "-O":
                        continue  # Skip OS detection
                    elif arg == "-A":
                        safe_arguments.extend(["-sV", "-sC"])  # Version and script scan only
                    else:
                        safe_arguments.append(arg)
                
                final_arguments = " ".join(safe_arguments)
                print(f"Updated arguments: {final_arguments}")
                requires_root = False
    
    # Confirm scan
    confirm = input("\nProceed with scan? (y/N): ").strip().lower()
    if confirm != 'y':
        print("Scan cancelled.")
        return None
    
    try:
        print("\nCreating scanner...")
        
        # Handle different port specifications
        if ports.startswith("--top-ports"):
            # For top-ports, we need to use arguments instead of ports parameter
            scanner = nm.NmapScanner(target, arguments=f"{final_arguments} {ports}")
        else:
            # For specific ports or ranges
            scanner = nm.NmapScanner(target, ports=ports, arguments=final_arguments)
        
        print("Starting port scan...")
        print("This may take a while depending on the number of ports and timing settings...")
        
        scanner.run()
        print("Scan completed successfully!")
        
        # Process and display results
        try:
            scanned_hosts = scanner.scanned_hosts()
            if not scanned_hosts:
                print("No hosts found or responded!")
                return scanner
            
            print(f"\nScan Results - Found {len(scanned_hosts)} host(s):")
            print("="*60)
            
            for host in scanned_hosts:
                print(f"\nHost: {host}")
                try:
                    host_state = scanner.state(host)
                    print(f"State: {host_state}")
                    
                    if host_state == "up":
                        print(f"Reason: {scanner.reason(host)}")
                        
                        # Get hostnames if available
                        hostnames = scanner.hostnames(host)
                        if hostnames:
                            print(f"Hostnames: {', '.join(hostnames)}")
                        
                        # Show open ports
                        protocols = scanner.all_protocols(host)
                        open_ports = []
                        closed_ports = []
                        filtered_ports = []
                        
                        for proto in protocols:
                            ports_list = scanner.scanned_ports(host, proto)
                            for port in ports_list:
                                try:
                                    port_state, port_reason = scanner.port_state(host, proto, port)
                                    port_info = f"{port}/{proto}"
                                    
                                    if port_state == "open":
                                        # Try to get service info
                                        try:
                                            service = scanner.service(host, proto, port)
                                            if service and service.get('name'):
                                                port_info += f" ({service['name']}"
                                                if service.get('version'):
                                                    port_info += f" {service['version']}"
                                                port_info += ")"
                                        except:
                                            pass
                                        open_ports.append(port_info)
                                    elif port_state == "closed":
                                        closed_ports.append(f"{port}/{proto}")
                                    elif port_state == "filtered":
                                        filtered_ports.append(f"{port}/{proto}")
                                        
                                except Exception as port_error:
                                    print(f"Error getting port {port}/{proto} details: {port_error}")
                        
                        # Display port results
                        if open_ports:
                            print(f"Open ports ({len(open_ports)}):")
                            for port in open_ports:
                                print(f"  {port}")
                        
                        if filtered_ports:
                            print(f"Filtered ports ({len(filtered_ports)}):")
                            for port in filtered_ports[:10]:  # Limit display
                                print(f"  {port}")
                            if len(filtered_ports) > 10:
                                print(f"  ... and {len(filtered_ports) - 10} more")
                        
                        if closed_ports:
                            print(f"Closed ports: {len(closed_ports)} (not shown)")
                        
                        # Show OS detection if available
                        try:
                            os_info = scanner.os(host)
                            if os_info:
                                print(f"OS Detection: {os_info}")
                        except:
                            pass
                    
                except Exception as host_error:
                    print(f"Error processing host {host}: {host_error}")
                
                print("-" * 40)
        
        except Exception as results_error:
            print(f"Error processing scan results: {results_error}")
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
            print("2. Use TCP Connect scan (-sT) instead of SYN scan (-sS)")
            print("3. Avoid OS detection (-O) and UDP scans (-sU)")
            print("4. Try the scan again and select 'TCP Connect Scan' option")
        elif "no output" in error_msg.lower():
            print("\n🔧 NO OUTPUT ERROR SOLUTIONS:")
            print("1. Check if the target is reachable: ping", target)
            print("2. Try with different timing settings (slower)")
            print("3. Use TCP Connect scan instead of SYN scan")
            print("4. Add -Pn flag to skip host discovery")
        
        return None
    except Exception as e:
        print(f'Unexpected error: {e}')
        print("\n🔧 GENERAL TROUBLESHOOTING:")
        print("1. Check network connectivity to target")
        print("2. Verify target IP address format")
        print("3. Try with simpler scan options")
        print("4. Run with sudo if using advanced scan types")
        return None


def export_port_scan_to_dict(scanner):
    """
    Export nmapthon port scan results to a structured dictionary format.
    
    Args:
        scanner: nmapthon.NmapScanner object with completed scan results
        
    Returns:
        dict: Structured dictionary containing all port scan data
    """
    if not scanner:
        return {"error": "No scanner object provided"}
    
    try:
        # Initialize the main scan data dictionary
        scan_data = {
            "scan_info": {
                "timestamp": datetime.datetime.now().isoformat(),
                "scanner_type": "nmapthon",
                "scan_type": "port_scan",
                "scan_status": "completed"
            },
            "hosts": {},
            "summary": {
                "total_hosts": 0,
                "hosts_up": 0,
                "hosts_down": 0,
                "total_open_ports": 0,
                "total_closed_ports": 0,
                "total_filtered_ports": 0
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
                    "os_info": {},
                    "scan_time": datetime.datetime.now().isoformat(),
                    "port_summary": {
                        "open": 0,
                        "closed": 0,
                        "filtered": 0
                    }
                }
                
                try:
                    # Get host state and reason
                    host_state = scanner.state(host)
                    host_data["state"] = host_state
                    
                    if host_state == "up":
                        scan_data["summary"]["hosts_up"] += 1
                        host_data["reason"] = scanner.reason(host)
                        
                        # Get hostnames
                        try:
                            hostnames = scanner.hostnames(host)
                            if hostnames:
                                host_data["hostnames"] = list(hostnames)
                        except:
                            pass
                        
                        # Get OS information if available
                        try:
                            os_info = scanner.os(host)
                            if os_info:
                                host_data["os_info"] = os_info
                        except:
                            pass
                        
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
                                    
                                    port_info = {
                                        "state": port_state,
                                        "reason": port_reason,
                                        "service": {}
                                    }
                                    
                                    # Get service information
                                    try:
                                        service = scanner.service(host, proto, port)
                                        if service:
                                            port_info["service"] = service
                                    except:
                                        pass
                                    
                                    host_data["ports"][proto][str(port)] = port_info
                                    
                                    # Update counters
                                    if port_state == "open":
                                        host_data["port_summary"]["open"] += 1
                                        scan_data["summary"]["total_open_ports"] += 1
                                    elif port_state == "closed":
                                        host_data["port_summary"]["closed"] += 1
                                        scan_data["summary"]["total_closed_ports"] += 1
                                    elif port_state == "filtered":
                                        host_data["port_summary"]["filtered"] += 1
                                        scan_data["summary"]["total_filtered_ports"] += 1
                                        
                                except Exception as port_error:
                                    host_data["ports"][proto][str(port)] = {
                                        "state": "error",
                                        "reason": str(port_error),
                                        "service": {}
                                    }
                    else:
                        scan_data["summary"]["hosts_down"] += 1
                    
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
            "error": f"Failed to export port scan data: {str(e)}",
            "timestamp": datetime.datetime.now().isoformat()
        }


def print_port_scan_summary(scan_dict):
    """
    Print a formatted summary of the port scan results from the dictionary.
    
    Args:
        scan_dict: Dictionary containing scan results from export_port_scan_to_dict()
    """
    if "error" in scan_dict:
        print(f"Error in scan data: {scan_dict['error']}")
        return
    
    print("\n" + "="*70)
    print("PORT SCAN SUMMARY")
    print("="*70)
    
    # Print scan info
    scan_info = scan_dict.get("scan_info", {})
    print(f"Timestamp: {scan_info.get('timestamp', 'Unknown')}")
    print(f"Scan Type: {scan_info.get('scan_type', 'Unknown')}")
    print(f"Status: {scan_info.get('scan_status', 'Unknown')}")
    if "command" in scan_info:
        print(f"Command: {scan_info['command']}")
    
    # Print summary statistics
    summary = scan_dict.get("summary", {})
    print(f"\nScan Summary:")
    print(f"  Total hosts: {summary.get('total_hosts', 0)}")
    print(f"  Hosts up: {summary.get('hosts_up', 0)}")
    print(f"  Hosts down: {summary.get('hosts_down', 0)}")
    print(f"  Total open ports: {summary.get('total_open_ports', 0)}")
    print(f"  Total closed ports: {summary.get('total_closed_ports', 0)}")
    print(f"  Total filtered ports: {summary.get('total_filtered_ports', 0)}")
    
    # Print detailed host information
    hosts = scan_dict.get("hosts", {})
    if hosts:
        print(f"\nDetailed Host Information:")
        print("-" * 50)
        
        for ip, host_data in hosts.items():
            print(f"\nHost: {ip}")
            print(f"  State: {host_data.get('state', 'unknown')}")
            
            if host_data.get('state') == 'up':
                print(f"  Reason: {host_data.get('reason', 'unknown')}")
                
                hostnames = host_data.get("hostnames", [])
                if hostnames:
                    print(f"  Hostnames: {', '.join(hostnames)}")
                
                # Port summary
                port_summary = host_data.get("port_summary", {})
                print(f"  Port Summary: {port_summary.get('open', 0)} open, "
                      f"{port_summary.get('closed', 0)} closed, "
                      f"{port_summary.get('filtered', 0)} filtered")
                
                # Show open ports with services
                ports = host_data.get("ports", {})
                open_ports = []
                
                for proto, port_dict in ports.items():
                    for port_num, port_info in port_dict.items():
                        if port_info.get("state") == "open":
                            service_info = port_info.get("service", {})
                            port_display = f"{port_num}/{proto}"
                            
                            if service_info.get('name'):
                                port_display += f" ({service_info['name']}"
                                if service_info.get('version'):
                                    port_display += f" {service_info['version']}"
                                port_display += ")"
                            
                            open_ports.append(port_display)
                
                if open_ports:
                    print(f"  Open Ports:")
                    for port in open_ports:
                        print(f"    {port}")
                
                # OS information
                os_info = host_data.get("os_info")
                if os_info:
                    print(f"  OS Detection: {os_info}")
    
    print("="*70)