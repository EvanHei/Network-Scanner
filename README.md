# Network Scanner

A simple network tool for scanning the local network to identify active devices, detect open ports, reverse-resolve hostnames, fingerprint device vendors, and track changes over time.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Guide](#guide)
3. [Technologies](#technologies)

## Getting Started

<summary><strong>Run from source code</strong></summary>

1. Install Python 3.10+ from [python.org](https://www.python.org/downloads/), or verify with:

   ```bash
   python --version
   ```
2. Run the scanner:

   ```bash
    python scanner.py
   ```

## Guide

### Scan Output

After running the script, you’ll see:

- Active devices on your local network
- IP address, MAC address, vendor name, hostname (if available)
- Detected open ports on common services (e.g., 80, 443, 9100)

### Device Tracking

Each device is stored in a local SQLite database to track network assests over time.

- **New Devices**: IPs/MACs seen for the first time
- **Left Devices**: Devices no longer found
- **Total Devices**: Running count across all scans

## Technologies

- **Language**: Python
- **Version Control**: Git
- **Concurrency**: parallel port scanning
- **Networking**: ARP / IP addresses, DNS, ports
- **Database**: SQLite
- **OS**: Windows
