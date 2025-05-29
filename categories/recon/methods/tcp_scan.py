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
    parser.add_argument('--port', '-p', type=str, default=None, help='Comma-separated list of ports (e.g., 80,443)')
    args, unknown = parser.parse_known_args(extra_args)
    if unknown:
        print(f"[!] Warning: Unknown TCP scan options ignored: {unknown}")

    if args.port:
        try:
            ports = [int(p.strip()) for p in args.port.split(',')]
            for port in ports:
                if port < 1 or port > 65535:
                    raise ValueError(f"Port {port} out of valid range 1-65535")
            args.port = ports
        except ValueError as e:
            print(f"[!] Invalid port list: {e}")
            exit(1)
    else:
        args.port = None

    return args

def print_banner(stealth):
    scan_type = "STEALTH (SYN)" if stealth else "CONNECT"
    print(f"\n{'-'*60}")
    print(colored(f"[+] Starting TCP {scan_type} host discovery scan", "cyan"))
    print(f"{'-'*60}")
    print(f"{'Host':<20}{'Status':<10}")
    print(f"{'-'*30}")

def print_host_result(ip, status):
    status_colors = {
        "ACTIVE": "green",
        "INACTIVE": "red"
    }
    print(f"{str(ip):<20}{colored(status, status_colors.get(status, 'white'))}")

def tcp_scan(ip_range, tcp_flags):
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
    except ValueError:
        print(colored(f"[!] Invalid IP range: {ip_range}", "red"))
        return []

    # Validate ports if specified
    if tcp_flags.port:
        for port in tcp_flags.port:
            if port < 1 or port > 65535:
                print("[!] Invalid port number specified. Must be between 1 and 65535.")
                return []
        ports = tcp_flags.port
    else:
        ports = COMMON_PORTS

    if tcp_flags.stealth:
        return tcp_stealth_scan(network, ports)
    else:
        return tcp_connect_scan(network, ports)

def tcp_connect_scan(network, ports):
    active_hosts = []

    print_banner(stealth=False)

    for ip in network.hosts():
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((str(ip), port))
                sock.close()
                if result == 0:
                    print_host_result(ip, "ACTIVE")
                    active_hosts.append(str(ip))
                    break
            except Exception as e:
                print(f"[!] Error scanning {ip}:{port} - {e}")
        else:
            print_host_result(ip, "INACTIVE")

    return active_hosts

def tcp_stealth_scan(network, ports):
    active_hosts = []

    print_banner(stealth=True)

    for ip in network.hosts():
        for port in ports:
            try:
                pkt = IP(dst=str(ip)) / TCP(dport=port, flags='S')
                resp = sr1(pkt, timeout=1, verbose=0)
                if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
                    sr1(IP(dst=str(ip)) / TCP(dport=port, flags='R'), timeout=1, verbose=0)
                    print_host_result(ip, "ACTIVE")
                    active_hosts.append(str(ip))
                    break
            except Exception as e:
                print(f"[!] Error scanning {ip}:{port} - {e}")
        else:
            print_host_result(ip, "INACTIVE")

    return active_hosts