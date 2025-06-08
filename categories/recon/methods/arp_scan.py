from scapy.all import ARP, Ether, srp
from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_network
from termcolor import colored
from colorama import init
from utils import handle_scan_output,resolve_hostname
import time

init()

def print_arp_banner():
    print("\n" + "-"*50)
    print(colored("[+] Starting ARP host discovery scan", "cyan"))
    print("-"*50)
    print(f"{'Hostname':<20}{'IP':<20}{'Status':<10}")
    print("-"*50)

def print_arp_result(hostname, ip, status):
    status_colors = {
        "ACTIVE": "green",
        "INACTIVE": "red"
    }
    print(f"{hostname:<20}{ip:<20}{colored(status, status_colors.get(status, 'white'))}")

def arp_scan(target_ip, timeout, retries, filename, ftype, silent, max_workers=50):
    try:
        network = ip_network(target_ip, strict=False)
    except ValueError:
        print(f"[!] Invalid IP or network range: '{target_ip}'")
        return []

    if not silent:
        print_arp_banner()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(lambda ip: arp_request_ip(ip,timeout,retries), network.hosts())

    active_ips = []
    for hostname, ip, active, mac in results:
        status = "ACTIVE" if active else "INACTIVE"
        if not silent:
            print_arp_result(hostname, ip, status)
        active_ips.append({
            "hostname": hostname,
            "ip": ip,
            "mac": mac,
            "status": status
        })

    handle_scan_output(active_ips, scantype="ARP", filename=filename, ftype=ftype)       
        
    return active_ips

def arp_request_ip(ip,timeout,retries):
    arp_req = ARP(pdst=str(ip))
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_req
    hostname = "Unknown"
    mac = "Unknown"

    for attempt in range(retries):
        ans, _ = srp(packet, timeout=timeout, verbose=False)
        if ans:
            mac = ans[0][1].hwsrc
            hostname = resolve_hostname(ip)
            return (hostname, str(ip), True, mac)
        time.sleep(0.1)

    return (hostname, str(ip), False, mac)