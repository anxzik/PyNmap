#imports

import nmapthon as nm
from subnet_info import SubnetInfo

from host_discovery import host_discovery
from port_scanner import port_scanner
from results import process_scan_results, print_results_summary, export_current_results

_subnet = SubnetInfo()

#Menu displaying options to select scans, results, exports, or exit
print(f'Hello, Welcome to my NMAP Scanner! \nYour Current IP local address is \033[91m {_subnet.get_local_ip()}\033[0m\nYour Current Public IP address is \033[91m{_subnet.get_public_ip()}\033[0m')
def display_menu():
    print("\n---Network Address Mapping & Script Scanning Utility---")
    print("1. Host Discovery")
    print("2. Remote Port Scan")
    print("3. View Scan Results Summary")
    print("4. Export Results")
    print("5. Exit")

#Function Selections
def handle_option_a():
    print("You selected Host Discovery.")
    scanner = host_discovery(nm)
    if scanner:
        print("\nProcessing scan results...")
        process_scan_results(scanner, "host_discovery")
        print("Results processed and stored.")

def handle_option_b():
    print("You selected Remote Port Scan.")
    scanner = port_scanner(nm)
    if scanner:
        print("\nProcessing scan results...")
        process_scan_results(scanner, "port_scan")
        print("Results processed and stored.")

def handle_option_c():
    print("Displaying scan results summary...")
    print_results_summary()

def handle_option_d():
    print("\n--- Export Results ---")
    print("1. Export to JSON")
    print("2. Export to CSV")
    
    export_choice = input("Select export format (1-2): ").strip()
    filename = input("Enter filename (or press Enter for auto-generated): ").strip()
    
    if not filename:
        filename = None
    
    if export_choice == "1":
        result = export_current_results("json", filename)
    elif export_choice == "2":
        result = export_current_results("csv", filename)
    else:
        print("Invalid choice.")
        return
    
    if result:
        print(f"Export successful: {result}")
    else:
        print("Export failed.")

def main():
    while True:
        display_menu()
        choice = input("Enter your choice: ")

        if choice == '1':
            handle_option_a()
        elif choice == '2':
            handle_option_b()
        elif choice == '3':
            handle_option_c()
        elif choice == '4':
            handle_option_d()
        elif choice == '5':
            print("Exiting the program. Goodbye!")
            break  # Exit the while loop
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()