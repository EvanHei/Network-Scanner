import subprocess
import re
import socket
import concurrent.futures
import sqlite3
import datetime

OUI_FILE = "oui.txt"
DB_FILE = "network_inventory.db"
COMMON_PORTS = [80, 443, 22, 23, 554, 9100, 445]

def get_interface_name_map():
    result = subprocess.run(['netsh', 'interface', 'ipv4', 'show', 'interfaces'],
                            capture_output=True, text=True)
    lines = result.stdout.splitlines()
    interface_map = {}
    for line in lines:
        match = re.match(r"\s*(\d+)\s+\S+\s+\S+\s+(.*)", line)
        if match:
            index = int(match.group(1))
            name = match.group(2).strip()
            interface_map[index] = name
    return interface_map

def load_oui_database(path=OUI_FILE):
    oui_map = {}
    with open(path, encoding='utf-8') as file:
        for line in file:
            if "(hex)" in line:
                parts = line.split("(hex)")
                if len(parts) == 2:
                    oui = parts[0].strip().replace("-", ":").lower()
                    vendor = parts[1].strip()
                    oui_map[oui] = vendor
    return oui_map

def get_vendor_from_mac(mac, oui_map):
    prefix = mac.lower()[0:8]
    return oui_map.get(prefix, "Unknown Vendor")

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

def classify_device(vendor, hostname, ports, os_guess="Unknown"):
    vendor = vendor.lower()
    hostname = hostname.lower()
    os_guess = os_guess.lower()

    if "printer" in hostname or 9100 in ports:
        return "Printer"
    if "router" in hostname or "broadband" in vendor or 445 in ports:
        return "Router"
    if any(x in vendor for x in ["samsung", "huawei", "apple", "xiaomi", "oneplus"]):
        return "Phone"
    if "pc" in hostname or "win" in os_guess:
        return "Windows PC"
    if "linux" in os_guess or 22 in ports:
        return "Linux Device"
    if "hp" in vendor and 9100 in ports:
        return "HP Printer"
    if "azurewave" in vendor:
        return "Smart Device / IoT"
    return "Unknown"

def scan_ports(ip, ports=COMMON_PORTS, timeout=0.5):
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            try:
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
            except:
                pass
    return open_ports

def resolve_host_and_ports(ip, oui_map, mac, type_):
    hostname = reverse_dns(ip)
    open_ports = scan_ports(ip)
    vendor = get_vendor_from_mac(mac, oui_map)
    device_type = classify_device(vendor, hostname, open_ports)
    return (ip, mac, vendor, hostname, open_ports, device_type)

def initialize_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            mac TEXT PRIMARY KEY,
            ip TEXT,
            vendor TEXT,
            hostname TEXT,
            device_type TEXT,
            open_ports TEXT,
            last_seen TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_time TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            scan_id INTEGER,
            mac TEXT,
            PRIMARY KEY (scan_id, mac),
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
            FOREIGN KEY (mac) REFERENCES devices(mac)
        )
    """)

    conn.commit()
    conn.close()

def save_scan_results(devices):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("INSERT INTO scans DEFAULT VALUES")
    scan_id = cursor.lastrowid

    now = datetime.datetime.now().isoformat()
    seen_macs = set()

    for device in devices:
        ip, mac, vendor, hostname, open_ports, device_type = device
        if mac in seen_macs:
            continue
        seen_macs.add(mac)

        ports_str = ",".join(str(p) for p in open_ports) if open_ports else "-"

        cursor.execute("""
            INSERT INTO devices (mac, ip, vendor, hostname, device_type, open_ports, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                ip=excluded.ip,
                vendor=excluded.vendor,
                hostname=excluded.hostname,
                device_type=excluded.device_type,
                open_ports=excluded.open_ports,
                last_seen=excluded.last_seen
        """, (mac, ip, vendor, hostname, device_type, ports_str, now))

        cursor.execute("INSERT INTO scan_results (scan_id, mac) VALUES (?, ?)", (scan_id, mac))

    # Compare with previous scan
    cursor.execute("SELECT scan_id FROM scans WHERE scan_id < ? ORDER BY scan_id DESC LIMIT 1", (scan_id,))
    prev_scan = cursor.fetchone()

    new_devices = 0
    left_devices = 0

    if prev_scan:
        prev_scan_id = prev_scan[0]
        # New devices (current minus previous)
        cursor.execute("""
            SELECT mac FROM scan_results WHERE scan_id = ?
            EXCEPT
            SELECT mac FROM scan_results WHERE scan_id = ?
        """, (scan_id, prev_scan_id))
        new_devices = len(cursor.fetchall())

        # Left devices (previous minus current)
        cursor.execute("""
            SELECT mac FROM scan_results WHERE scan_id = ?
            EXCEPT
            SELECT mac FROM scan_results WHERE scan_id = ?
        """, (prev_scan_id, scan_id))
        left_devices = len(cursor.fetchall())

    cursor.execute("SELECT COUNT(*) FROM devices")
    total_devices = cursor.fetchone()[0]

    conn.commit()
    conn.close()

    return {
        "new_devices": new_devices,
        "left_devices": left_devices,
        "total_devices": total_devices
    }

def show_arp_with_details():
    interface_names = get_interface_name_map()
    oui_map = load_oui_database()

    result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
    lines = result.stdout.splitlines()

    current_interface_index = None
    entries_to_scan = []

    for line in lines:
        interface_match = re.match(r'^Interface:\s+(\d+\.\d+\.\d+\.\d+)\s+---\s+0x([0-9a-fA-F]+)', line)
        if interface_match:
            ip = interface_match.group(1)
            hex_index = interface_match.group(2)
            current_interface_index = int(hex_index, 16)
            name = interface_names.get(current_interface_index, "Unknown Interface")

            # Only process Ethernet subnet (example 192.168.1.x)
            if not ip.startswith("192.168.1."):
                current_interface_index = None
            else:
                print(f"\nInterface: {ip} --- 0x{hex_index} ({name})")
                print(f"{'IP Address':<17} {'MAC Address':<20} {'Vendor':<35} {'Hostname':<30} {'Device Type':<15} Open Ports")
            continue

        if current_interface_index is None:
            continue

        entry_match = re.match(r'\s*(\d+\.\d+\.\d+\.\d+)\s+([a-fA-F0-9\-]+)\s+(\w+)', line)
        if entry_match:
            ip = entry_match.group(1)
            mac = entry_match.group(2).replace("-", ":").lower()
            type_ = entry_match.group(3)
            entries_to_scan.append((ip, mac, type_))

    devices = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(resolve_host_and_ports, ip, oui_map, mac, type_)
                   for ip, mac, type_ in entries_to_scan]

        for future in concurrent.futures.as_completed(futures):
            ip, mac, vendor, hostname, open_ports, device_type = future.result()
            ports_str = ",".join(str(p) for p in open_ports) if open_ports else "-"
            print(f"{ip:<17} {mac:<20} {vendor:<35} {hostname:<30} {device_type:<15} {ports_str}")
            devices.append((ip, mac, vendor, hostname, open_ports, device_type))

    return devices

if __name__ == "__main__":
    initialize_db()
    devices = show_arp_with_details()
    summary = save_scan_results(devices)

    print("\n" + "=" * 90)
    print(f"{'Summary':^90}")
    print("=" * 90)
    print(f"{'New Devices':<15} {'Left Devices':<15} {'Total Devices':<15}")
    print(f"{summary['new_devices']:<15} {summary['left_devices']:<15} {summary['total_devices']:<15}")
