from scapy.all import IP, ICMP, sr1
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored
from colorama import init
from ipaddress import ip_network

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

def ping_ip(ip):
    try:
        pkt = IP(dst=str(ip)) / ICMP()
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp:
            return (str(ip), True)
    except Exception:
        pass
    return (str(ip), False)

def icmp_scan(target_ip, max_workers=50):
    try:
        network = ip_network(target_ip, strict=False)
    except ValueError:
        print(f"[!] Invalid IP or network range: '{target_ip}'")
        return []

    print_icmp_banner()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(ping_ip, network.hosts())

    active_ips = []

    for ip, is_up in results:
        try:
            if is_up:
                print_icmp_result(str(ip), "ACTIVE")
                active_ips.append(str(ip))
            else:
                print_icmp_result(str(ip), "INACTIVE")
        except Exception as e:
            print(f"[!] Error probing {ip}: {e}")

    return active_ips