from scapy.all import IP, ICMP, sr1
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored
from colorama import init
from ipaddress import ip_network
from utils import handle_scan_output
import time

init()

def print_icmp_banner():
    print("\n" + "-"*60)
    print(colored("[+] Starting ICMP host discovery scan", "cyan"))
    print("-"*60)
    print(f"{'Host':<20}{'Status':<10}")
    print("-"*30)

def print_icmp_result(ip, status):
    status_colors = {
        "ACTIVE": "green",
        "INACTIVE": "red"
    }
    print(f"{ip:<20}{colored(status, status_colors.get(status, 'white'))}")

def icmp_scan(target_ip, timeout, retries, filename, ftype, max_workers=50):
    try:
        network = ip_network(target_ip, strict=False)
    except ValueError:
        print(f"[!] Invalid IP or network range: '{target_ip}'")
        return []

    print_icmp_banner()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(lambda ip: ping_ip(ip, timeout, retries), network.hosts())

    active_ips = []

    for ip, active in results:
        status = "ACTIVE" if active else "INACTIVE"
        print_icmp_result(ip, status)
        active_ips.append({
            "ip": ip,
            "status": status
        })

    handle_scan_output(active_ips, scantype="ICMP", filename=filename, ftype=ftype) 

    return active_ips

def ping_ip(ip, timeout, retries):
    try:
        pkt = IP(dst=str(ip)) / ICMP()

        for attempt in range(retries):
            resp = sr1(pkt, timeout, verbose=0)
            if resp:
                return (str(ip), True)
            time.sleep(0.1)
    except Exception:
        pass
    return (str(ip), False)