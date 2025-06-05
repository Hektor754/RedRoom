from scapy.all import IP, TCP, sr1
from termcolor import colored
from colorama import init
from concurrent.futures import ThreadPoolExecutor
from utils import handle_scan_output,resolve_hostname
import time
import argparse
import socket
import ipaddress

MAX_WORKERS = 50
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
    print(f"{'Hostname':<20}{'Host':<20}{'Status':<10}")
    print(f"{'-'*60}")

def print_host_result(hostname, ip, status):
    status_colors = {
        "ACTIVE": "green",
        "INACTIVE": "red"
    }
    print(f"{hostname:<20}{str(ip):<20}{colored(status, status_colors.get(status, 'white'))}")

def tcp_scan(ip_range, tcp_flags, timeout, retries, filename, ftype, max_workers=MAX_WORKERS):
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
    except ValueError:
        print(colored(f"[!] Invalid IP range: {ip_range}", "red"))
        return []

    ports = tcp_flags.port if tcp_flags.port else COMMON_PORTS

    if tcp_flags.stealth:
        return tcp_stealth_scan(network, ports, timeout, retries, filename, ftype)
    else:
        return tcp_connect_scan(network, ports, max_workers, timeout, retries, filename, ftype)

def tcp_connect_scan(network, ports, timeout, retries, filename, ftype, max_workers=MAX_WORKERS):
    active_hosts = []
    print_banner(stealth=False)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(lambda ip: connect_ip_host(ip, ports, timeout, retries), network.hosts())

    for hostname, ip, active in results:
        status = "ACTIVE" if active else "INACTIVE"
        print_host_result(hostname, ip, status)
        active_hosts.append({
            "hostname": hostname,
            "ip": ip,
            "status": status
        })

    handle_scan_output(active_hosts, scantype="TCP connect", filename=filename, ftype=ftype) 

    return active_hosts

def tcp_stealth_scan(network, ports, timeout, retries, filename, ftype, max_workers= MAX_WORKERS):
    active_hosts = []
    print_banner(stealth=True)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(lambda ip: stealth_scan_ip(ip, ports, timeout, retries), network.hosts())

    for hostname, ip, active in results:
        status = "ACTIVE" if active else "INACTIVE"
        print_host_result(hostname, ip, status)
        active_hosts.append({
            "hostname": hostname,
            "ip": ip,
            "status": status
        })

    handle_scan_output(active_hosts, scantype="TCP stealth", filename=filename, ftype=ftype)

    return active_hosts

def connect_ip_host(ip, ports, timeout, retries):
    hostname = "Unknown"
    for port in ports:
        try:
            for _ in range(retries):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((str(ip), port))
                sock.close()
                if result == 0:
                    hostname = resolve_hostname(ip)
                    return (hostname, str(ip), True)
                time.sleep(0.1)
        except Exception:
            pass
    return (hostname, str(ip), False)

def stealth_scan_ip(ip, ports, timeout, retries):
    hostname = "Unknown"
    for port in ports:
        try:
            for _ in range(retries):
                pkt = IP(dst=str(ip)) / TCP(dport=port, flags='S')
                resp = sr1(pkt, timeout, verbose=0)
                if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
                    sr1(IP(dst=str(ip)) / TCP(dport=port, flags='R'), timeout, verbose=0)
                    hostname = resolve_hostname(ip)
                    return (hostname, str(ip), True)
                time.sleep(0.1)
        except Exception:
            pass
    return (hostname,str(ip), False)