import csv
import json
import os
import socket
import ipaddress
import ifaddr
import subprocess


def print_summary(results,scantype):
    total = len(results)
    active_hosts = sum(1 for r in results if r["status"] == "ACTIVE")
    down_hosts = total - active_hosts

    print(f"\n {scantype} scan summary: ")
    print(f"-Total hosts scanned: {total}")
    print(f"-Hosts active: {active_hosts}")
    print(f"-Hosts down: {down_hosts}")

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
        target_addr = ipaddress.IPv4Address(target_ip)
        adapters = ifaddr.get_adapters()

        for adapter in adapters:
            for ip in adapter.ips:
                if isinstance(ip.ip, tuple):
                    continue

                local_ip = ip.ip
                network = ipaddress.IPv4Network(f"{local_ip}/{ip.network_prefix}", strict=False)

                if target_addr in network:
                    try:
                        output = subprocess.check_output(
                            ['nmblookup', '-A', target_ip],
                            stderr=subprocess.DEVNULL,
                            timeout=3
                        ).decode(errors='ignore')

                        for line in output.splitlines():
                            if '<00>' in line and 'GROUP' not in line:
                                hostname = line.split()[0]
                                if hostname:
                                    return hostname
                    except Exception:
                        pass
        try:
            hostname, _, _ = socket.gethostbyaddr(target_ip)
            return hostname
        except Exception:
            return "Unknown"