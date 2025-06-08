from termcolor import colored
import csv
import json
import os
import socket
import ipaddress
import ifaddr
import subprocess
import shutil
import platform
import re

def print_hostprofile_results(results):
    print("\n" + "-" * 90)
    print(f"{'Hostname':<20}{'IP Address':<18}{'MAC Address':<20}{'Vendor':<30}{'Status':<10}")
    print("-" * 90)

    for host in results:
        hostname = host.get("hostname", "Unknown")
        ip = host.get("ip", "Unknown")
        mac = host.get("mac", "Unknown")
        vendor = host.get("vendor", "Unknown")
        status = host.get("status", "INACTIVE")

        status_colored = colored(status, "green" if status == "ACTIVE" else "red")

        print(f"{hostname:<20}{ip:<18}{mac:<20}{vendor:<30}{status_colored:<10}")

    print("-" * 90)

def print_summary(results,scantype):
    total = len(results)
    active_hosts = sum(1 for r in results if r["status"] == "ACTIVE")
    down_hosts = total - active_hosts

    print(f"\n {scantype} scan summary: ")
    print(f"-Total hosts scanned: {total}")
    print(f"-Hosts active: {active_hosts}")
    print(f"-Hosts inactive: {down_hosts}")

def save_results_csv(results, filename):
    with open(filename, mode="w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["hostname", "ip", "status"])
        writer.writeheader()
        writer.writerows(results)
    print(f"\n[+] results saved to {filename}")

def save_results_json(results,filename):
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Results saved to {filename}")

def handle_scan_output(results, scantype, filename=None, ftype=None):
    print_summary(results, scantype=scantype)

    if ftype and not filename:
        filename = f"scan_output.{ftype}"

    if filename and not ftype:
        ext = os.path.splitext(filename)[1].lower()
        if ext == ".csv":
            ftype = "csv"
        elif ext == ".json":
            ftype = "json"

    if filename:
        if ftype not in ("csv", "json"):
            print(f"[!] Unsupported output format: {ftype}")
        elif ftype == "csv":
            save_results_csv(results, filename)
        elif ftype == "json":
            save_results_json(results, filename)

def resolve_hostname(target_ip):
    if isinstance(target_ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        target_ip = str(target_ip)

    try:
        target_addr = ipaddress.ip_address(target_ip)
    except ValueError:
        return "Invalid IP"
    
    def mdns_lookup():
        if shutil.which("avahi-resolve-address") is None:
            return "Unknown"
        try:
            output = subprocess.check_output(
                ["avahi-resolve-address", target_ip],
                stderr=subprocess.DEVNULL,
                timeout=2,
                encoding='utf-8'                
            )
            parts = output.strip().split()
            if len(parts) >= 2:
                return parts[1]
        except Exception:
            pass
        return None

    def netbios_lookup_nmblookup():
        if shutil.which("nmblookup") is None:
            return None
        adapters = ifaddr.get_adapters()
        for adapter in adapters:
            for ip in adapter.ips:
                if not isinstance(ip.ip, str):
                    continue
                try:
                    network = ipaddress.ip_network(f"{ip.ip}/{ip.network_prefix}", strict=False)
                except ValueError:
                    continue
                if target_addr in network:
                    try:
                        output = subprocess.check_output(
                            ['nmblookup', '-A', target_ip],
                            stderr=subprocess.DEVNULL,
                            timeout=3
                        ).decode(errors='ignore')
                        for line in output.splitlines():
                            if '<00>' in line and 'GROUP' not in line:
                                parts = line.strip().split()
                                if parts:
                                    return parts[0]
                    except Exception:
                        continue
        return None

    def netbios_lookup_nbtstat():
        if platform.system() != "Windows":
            return None
        try:
            output = subprocess.check_output(
                ['nbtstat', '-A', target_ip],
                stderr=subprocess.DEVNULL,
                timeout=3,
                encoding='utf-8',
                errors='ignore'
            )
            for line in output.splitlines():
                if '<00>' in line and 'UNIQUE' in line.upper():
                    parts = re.split(r'\s+', line.strip())
                    if parts:
                        return parts[0]
        except Exception:
            return None
        return None

    try:
        hostname, _, _ = socket.gethostbyaddr(target_ip)
        if hostname:
            return hostname
    except Exception:
        pass

    hostname = netbios_lookup_nmblookup()
    if hostname:
        return hostname

    hostname = netbios_lookup_nbtstat()
    if hostname:
        return hostname
    
    hostname = mdns_lookup()
    if hostname:
        return hostname

    try:
        fqdn = socket.getfqdn(target_ip)
        if fqdn and fqdn != target_ip:
            hostname = fqdn
            return hostname
    except Exception:
        pass

    return "Unknown"