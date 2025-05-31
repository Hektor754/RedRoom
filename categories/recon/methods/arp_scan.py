from scapy.all import ARP, Ether, srp
from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_network
from termcolor import colored
from colorama import init

init()

def print_arp_banner():
    print("\n" + "-"*60)
    print(colored("[+] Starting ARP host discovery scan", "cyan"))
    print("-"*60)
    print(f"{'Host':<20}{'Status':<10}")
    print("-"*30)

def print_arp_result(ip, status):
    status_colors = {
        "ACTIVE": "green",
        "INACTIVE": "red"
    }
    print(f"{ip:<20}{colored(status, status_colors.get(status, 'white'))}")

def arp_scan(target_ip, max_workers=50):
    try:
        network = ip_network(target_ip, strict=False)
    except ValueError:
        print(f"[!] Invalid IP or network range: '{target_ip}'")
        return []

    print_arp_banner()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(arp_request_ip, network.hosts())

    active_ips = []
    for ip, active in results:
        if active:
            print_arp_result(ip, "ACTIVE")
            active_ips.append(ip)
        else:
            print_arp_result(ip, "INACTIVE")

    return active_ips

def arp_request_ip(ip):
    arp_req = ARP(pdst=str(ip))
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_req
    ans, _ = srp(packet, timeout=1, verbose=False)
    for sent, received in ans:
        return (str(ip), True)
    return (str(ip), False)