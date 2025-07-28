# NMAP Scanner Permission Guide

## Overview
This NMAP scanner provides various scanning options, some of which require root/administrator privileges to function properly. This guide explains which features require elevated privileges and how to handle permission issues.

## Permission Requirements

### ✅ **No Root Required (Safe Options)**
These scan types work without elevated privileges:

- **TCP Connect Scan (-sT)** ⭐ **RECOMMENDED**
  - Most reliable for general port scanning
  - Works on all systems without special privileges
  - Slightly slower than SYN scan but more compatible

- **Version Detection (-sV)**
  - Service version identification
  - Works without root privileges

- **Script Scanning (-sC)**
  - NSE (Nmap Scripting Engine) scripts
  - Most scripts work without root

- **Skip Host Discovery (-Pn)**
  - Assumes target is up, skips ping
  - Useful when ICMP is blocked

### ⚠️ **Root Required (Advanced Options)**
These scan types require root/sudo privileges:

- **TCP SYN Scan (-sS)**
  - Faster than TCP Connect
  - Requires raw socket access
  - **Error**: "TCP/IP fingerprinting requires root privileges"

- **UDP Scan (-sU)**
  - Scans UDP ports
  - Requires raw socket access
  - Much slower than TCP scans

- **OS Detection (-O)**
  - Operating system fingerprinting
  - Requires raw packet manipulation
  - **Error**: "OS scan requires root privileges"

- **Aggressive Scan (-A)**
  - Combines OS detection, version detection, script scanning
  - Requires root due to OS detection component

- **Stealth Options (-f, timing)**
  - Packet fragmentation and advanced timing
  - May require raw socket access

## Common Error Messages

### "TCP/IP fingerprinting (for OS scan) requires root privileges. QUITTING!"
**Solution Options:**
1. Run with sudo: `sudo python __main__.py`
2. Select "TCP Connect Scan" instead of "SYN Scan"
3. Avoid OS detection option
4. Use the automatic fallback when prompted

### "No output from process was given"
**Solution Options:**
1. Check network connectivity: `ping <target>`
2. Use TCP Connect scan instead of SYN scan
3. Add `-Pn` flag to skip host discovery
4. Try slower timing settings

## Recommended Usage

### For Regular Users (No Root)
```bash
python __main__.py
# Select option 2 (Port Scanner)
# Choose:
# - Port Selection: Top 1000 ports (option 1)
# - Scan Type: TCP Connect Scan (option 2) ⭐
# - Additional: Version detection (option 2)
# - Timing: T4 Aggressive (option 5)
```

### For Advanced Users (With Root)
```bash
sudo python __main__.py
# Select option 2 (Port Scanner)
# Choose:
# - Port Selection: As needed
# - Scan Type: TCP SYN Scan (option 1) or Aggressive (option 5)
# - Additional: OS detection (option 1)
# - Timing: As needed
```

## Automatic Permission Handling

The scanner includes automatic permission detection and fallback:

1. **Permission Detection**: Automatically detects if running as root
2. **Warning System**: Warns when selected options require root
3. **Automatic Fallback**: Offers to convert SYN scans to TCP Connect
4. **Safe Defaults**: Defaults to TCP Connect when in doubt

## Best Practices

1. **Start Simple**: Use TCP Connect scans first
2. **Test Connectivity**: Ping target before scanning
3. **Use Appropriate Timing**: T4 for most cases, T3 for slower networks
4. **Escalate Gradually**: Try without root first, then with sudo if needed
5. **Check Firewall**: Ensure local firewall allows outbound connections

## Troubleshooting Steps

1. **Verify Target**: `ping <target_ip>`
2. **Check Connectivity**: Ensure network path is clear
3. **Try Safe Scan**: Use TCP Connect scan first
4. **Use Sudo**: If advanced features needed: `sudo python __main__.py`
5. **Check Logs**: Review error messages for specific guidance

## Platform-Specific Notes

### Linux/macOS
- Use `sudo` for elevated privileges
- Raw sockets require root access
- ICMP ping may require root

### Windows
- Run as Administrator for advanced features
- Some features may not work in all environments
- Consider using TCP Connect scans

## Support

If you encounter permission issues:
1. Check this guide for your specific error
2. Try the recommended solutions
3. Use the automatic fallback options when prompted
4. Start with TCP Connect scans for compatibility