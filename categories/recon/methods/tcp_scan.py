from scapy.all import IP, TCP, sr1, get_if_list, get_if_addr
import argparse
import socket
import ipaddress
from termcolor import colored
from colorama import init

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443]
init()

def parse_tcp_flags(extra_args):
    parser = argparse.ArgumentParser()
    parser.add_argument('--stealth', '-s', action='store_true', help='Perform stealth (SYN) scan')
    parser.add_argument('--port', '-p', type=int, default=80, help='Target port (default: 80)')
    return parser.parse_args(extra_args)

def get_own_ips():
    ips = []
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip and not ip.startswith("127."):
                ips.append(ip)
        except Exception:
            continue
    return ips

def print_banner(port, stealth):
    scan_type = "STEALTH (SYN)" if stealth else "CONNECT"
    print(f"\n{'-'*60}")
    print(colored(f"[+] Starting TCP {scan_type} scan on port {port}", "cyan"))
    print(f"{'-'*60}")
    print(f"{'Host':<20}{'Port':<10}{'Status':<10}")
    print(f"{'-'*40}")

def print_result(ip, port, status):
    status_colors = {
        "OPEN": "green",
        "CLOSED": "red",
        "FILTERED": "yellow",
        "TIMEOUT": "magenta"
    }
    print(f"{str(ip):<20}{str(port):<10}{colored(status, status_colors.get(status, 'white'))}")

def tcp_scan(ip_range, tcp_flags):
    return tcp_stealth_scan(ip_range, tcp_flags) if tcp_flags and tcp_flags.stealth else tcp_connect_scan(ip_range, tcp_flags)

def tcp_connect_scan(ip_range, tcp_flags=None):
    ports = [tcp_flags.port] if tcp_flags and hasattr(tcp_flags, 'port') else COMMON_PORTS
    open_hosts = []
    own_ips = get_own_ips()

    try:
        network = ipaddress.ip_network(ip_range, strict=False)
    except ValueError:
        print(colored(f"[!] Invalid IP range: {ip_range}", "red"))
        return open_hosts

    for port in ports:
        print_banner(port, stealth=False)
        for ip in network.hosts():
            if str(ip) in own_ips:
                continue
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((str(ip), port))
                sock.close()
                if result == 0:
                    print_result(ip, port, "OPEN")
                    open_hosts.append(str(ip))
                else:
                    print_result(ip, port, "CLOSED")
            except Exception as e:
                print_result(ip, port, "ERROR")
    return open_hosts

def tcp_stealth_scan(ip_range, tcp_flags):
    ports = [tcp_flags.port] if tcp_flags and hasattr(tcp_flags, 'port') else COMMON_PORTS
    open_hosts = []
    own_ips = get_own_ips()

    try:
        network = ipaddress.ip_network(ip_range, strict=False)
    except ValueError:
        print(colored(f"[!] Invalid IP range: {ip_range}", "red"))
        return open_hosts

    for port in ports:
        print_banner(port, stealth=True)
        for ip in network.hosts():
            if str(ip) in own_ips:
                continue
            pkt = IP(dst=str(ip)) / TCP(dport=port, flags='S')
            try:
                resp = sr1(pkt, timeout=1, verbose=0)
                if resp is None:
                    print_result(ip, port, "FILTERED")
                elif resp.haslayer(TCP):
                    tcp_layer = resp.getlayer(TCP)
                    if tcp_layer.flags == 0x12:
                        print_result(ip, port, "OPEN")
                        open_hosts.append(str(ip))
                        rst_pkt = IP(dst=str(ip)) / TCP(dport=port, flags='R')
                        sr1(rst_pkt, timeout=1, verbose=0)
                    elif tcp_layer.flags == 0x14:
                        print_result(ip, port, "CLOSED")
                    else:
                        print_result(ip, port, "UNKNOWN")
                else:
                    print_result(ip, port, "UNKNOWN")
            except Exception as e:
                print_result(ip, port, "ERROR")
    return open_hosts