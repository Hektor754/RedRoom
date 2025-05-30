from scapy.all import IP, ICMP, sr1
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

def icmp_scan(target_ip):
    try:
        network = ip_network(target_ip, strict=False)
    except ValueError:
        print(f"[!] Invalid IP or network range: '{target_ip}'")
        return []

    print_icmp_banner()
    active_ips = []

    for ip in network.hosts():
        try:
            response = sr1(IP(dst=str(ip)) / ICMP(), timeout=1, verbose=0)
            if response:
                print_icmp_result(str(ip), "ACTIVE")
                active_ips.append(str(ip))
            else:
                print_icmp_result(str(ip), "INACTIVE")
        except Exception as e:
            print(f"[!] Error probing {ip}: {e}")

    return active_ips