from scapy.all import ARP, Ether, srp
from termcolor import colored
from colorama import init
from ipaddress import ip_network, AddressValueError

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

def arp_scan(target_ip):
    try:
        network = ip_network(target_ip, strict=False)
    except ValueError:
        print(f"[!] Invalid IP or network range: '{target_ip}'")
        return []

    print_arp_banner()

    arp_request = ARP(pdst=str(network))
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    try:
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    except Exception as e:
        print(f"[!] Error sending packets: {e}")
        return []

    active_ips = {received.psrc for sent, received in answered_list}

    for ip in network.hosts():
        if str(ip) in active_ips:
            print_arp_result(str(ip), "ACTIVE")
        else:
            print_arp_result(str(ip), "INACTIVE")

    return list(active_ips)