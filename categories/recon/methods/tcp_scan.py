from scapy.all import IP, TCP, send, sr1
from termcolor import colored
from colorama import init
from concurrent.futures import ThreadPoolExecutor
from utils import handle_scan_output, resolve_hostname
import os
import time
import argparse
import ipaddress
import random
import sys
import inspect

init()
MAX_WORKERS = 50
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443]


class Handler:
    @staticmethod
    def parse_tcp_flags(extra_args):
        parser = argparse.ArgumentParser()
        parser.add_argument('--stealth', '-s', action='store_true', help='Perform stealth (SYN) scan')
        parser.add_argument('--port', '-p', type=str, default=None, help='Comma-separated list of ports (e.g., 80,443)')
        parser.add_argument('--fin', '-f', action='store_true', help='Perform FIN scan')
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
                sys.exit(1)
        else:
            args.port = None

        return args

    @staticmethod
    def tcp_scan(ip_range, tcp_flags, timeout=3, retries=1, filename=None, ftype=None, max_workers=MAX_WORKERS):
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
        except ValueError:
            print(colored(f"[!] Invalid IP range: {ip_range}", "red"))
            return []
        
        caller_frame = inspect.stack()[1]

        caller_filename = os.path.basename(caller_frame.filename)

        ports = tcp_flags.port if tcp_flags.port else COMMON_PORTS

        if tcp_flags.stealth:
            scan_func = SCAN_METHODS["stealth"]
        elif caller_filename == "auto_host.py":
            scan_func = SCAN_METHODS["hostname"]
        elif tcp_flags.fin:
            scan_func = SCAN_METHODS["FIN"]
        else:
            scan_func = SCAN_METHODS["connect"]

        return scan_func(network, ports, timeout, retries, filename, ftype, max_workers)


class Output:
    @staticmethod
    def print_banner(scan_type):
        if scan_type == "stealth" or scan_type == "connect":
            print(f"\n{'-'*40}")
            print(colored(f"[+] Starting TCP {scan_type} host discovery scan", "cyan"))
            print(f"{'-'*40}")
            print(f"{'Host':<20}{'Status':<10}")
            print(f"{'-'*40}")
        else:
            print(f"\n{'-'*40}")
            print(colored(f"[+] Starting TCP {scan_type} host discovery scan", "cyan"))
            print(f"{'-'*40}")
            print(f"{'Host':<20}{'Port':<10}")
            print(f"{'-'*40}")


    @staticmethod
    def print_host_result(ip, status):
        status_colors = {
            "ACTIVE": "green",
            "INACTIVE": "red"
        }
        print(f"{str(ip):<20}{colored(status, status_colors.get(status, 'white'))}")

    @staticmethod
    def print_FIN_host_result(ip, ports):
        ports_str = ", ".join(map(str, ports)) if ports else "-"
        print(f"{str(ip):<20}{colored(ports_str,'white')}")


class Utilities:
    @staticmethod
    def randomize_sport():
        return random.randint(49152, 65535)

    @staticmethod
    def randomize_seq():
        return random.getrandbits(32)

    @staticmethod
    def randomize_window():
        return random.choice([5840, 8192, 16384, 65535, 14600, 32120, 29200])

    @staticmethod
    def randomize_ttl():
        return random.choice([64, 128, 255])

    @staticmethod
    def randomize_time(scan_method):
        if scan_method == "stealth":
            return random.uniform(0.3, 1.5)
        elif scan_method == "connect":
            return random.uniform(0.05, 0.2)
        return 0.1


class TCPConnectScan:
    @staticmethod
    def scan(network, ports, timeout, retries, filename, ftype, max_workers=MAX_WORKERS):
        active_hosts = []
        Output.print_banner(scan_type="connect")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = executor.map(lambda ip: TCPConnectScan._connect_ip_host(ip, ports, timeout, retries), network.hosts())

        for ip, active in results:
            status = "ACTIVE" if active else "INACTIVE"
            Output.print_host_result(ip, status)
            active_hosts.append({
                "ip": ip,
                "status": status
            })

        handle_scan_output(active_hosts, scantype="TCP connect", filename=filename, ftype=ftype)
        return active_hosts

    @staticmethod
    def _connect_ip_host(ip, ports, timeout, retries):
        for port in ports:
            try:
                for _ in range(retries):
                    src_port = Utilities.randomize_sport()
                    seq_num = Utilities.randomize_seq()
                    window_size = Utilities.randomize_window()
                    ttl_value = Utilities.randomize_ttl()

                    syn_packet = IP(dst=str(ip), ttl=ttl_value) / TCP(sport=src_port, dport=port, flags="S", seq=seq_num, window=window_size)
                    syn_ack_response = sr1(syn_packet, timeout=timeout, verbose=0)

                    if syn_ack_response and syn_ack_response.haslayer(TCP):
                        tcp_layer = syn_ack_response.getlayer(TCP)
                        if tcp_layer.flags & 0x12 == 0x12:
                            ack_seq = seq_num + 1
                            ack_ack = tcp_layer.seq + 1
                            ack_packet = IP(dst=str(ip), ttl=ttl_value) / TCP(sport=src_port, dport=port, flags="A", seq=ack_seq, ack=ack_ack, window=window_size)
                            send(ack_packet, verbose=0)

                            rst_packet = IP(dst=str(ip), ttl=ttl_value) / TCP(sport=src_port, dport=port, flags="R", seq=ack_seq, ack=ack_ack)
                            send(rst_packet, verbose=0)

                            return (str(ip), True)
                    delay = Utilities.randomize_time("connect")
                    time.sleep(delay)
            except Exception as e:
                print(f"[!] Error scanning {ip}:{port} - {e}")
        return (str(ip), False)


class TCPStealthScan:
    @staticmethod
    def scan(network, ports, timeout, retries, filename, ftype, max_workers=MAX_WORKERS):
        active_hosts = []
        Output.print_banner(scan_type="stealth")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = executor.map(lambda ip: TCPStealthScan._stealth_scan_ip(ip, ports, timeout, retries), network.hosts())

        for ip, active in results:
            status = "ACTIVE" if active else "INACTIVE"
            Output.print_host_result(ip, status)
            active_hosts.append({
                "ip": ip,
                "status": status
            })

        handle_scan_output(active_hosts, scantype="TCP stealth", filename=filename, ftype=ftype)
        return active_hosts

    @staticmethod
    def _stealth_scan_ip(ip, ports, timeout, retries):
        for port in ports:
            try:
                for _ in range(retries):
                    src_port = Utilities.randomize_sport()
                    seq_num = Utilities.randomize_seq()
                    window_size = Utilities.randomize_window()
                    ttl_value = Utilities.randomize_ttl()

                    syn_packet = IP(dst=str(ip), ttl=ttl_value) / TCP(sport=src_port, dport=port, flags='S', seq=seq_num, window=window_size)
                    syn_ack_resp = sr1(syn_packet, timeout=timeout, verbose=0)

                    if syn_ack_resp and syn_ack_resp.haslayer(TCP):
                        tcp_layer = syn_ack_resp.getlayer(TCP)
                        if tcp_layer.flags & 0x12 == 0x12:
                            rst_packet = IP(dst=str(ip), ttl=ttl_value) / TCP(sport=src_port, dport=port, flags='R', seq=seq_num + 1, window=window_size)
                            send(rst_packet, verbose=0)
                            return (str(ip), True)
                    delay = Utilities.randomize_time("stealth")
                    time.sleep(delay)
            except Exception as e:
                print(f"[!] Error scanning {ip}:{port} - {e}")
        return (str(ip), False)
    
class TCPFINScan:
    @staticmethod
    def scan(network, ports, timeout, retries, filename, ftype, max_workers=MAX_WORKERS):
        active_hosts = []
        Output.print_banner(scan_type="FIN")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = executor.map(lambda ip: TCPFINScan._FIN_scan_ip(ip, ports, timeout, retries), network.hosts())

        for ip, ports in results:
            Output.print_FIN_host_result(ip, ports)
            active_hosts.append({
                "ip": ip,
                "ports": ports
            })
        
        return active_hosts
    
    @staticmethod
    def _FIN_scan_ip(ip, ports, timeout, retries):
        open_ports = []

        for port in ports:
            try:
                for _ in range(retries):
                    src_port = Utilities.randomize_sport()
                    seq_num = Utilities.randomize_seq()
                    window_size = Utilities.randomize_window()
                    ttl_value = Utilities.randomize_ttl()

                    fin_packet = IP(dst=str(ip), ttl=ttl_value) / TCP(sport=src_port,dport=port, flags="F", seq=seq_num, window=window_size)
                    response = sr1(fin_packet, timeout=timeout, verbose=0)

                    if response is None:
                        open_ports.append(port)

                    if response and response.haslayer(TCP):
                        if response.getlayer(TCP).flags == 0x14:
                            continue
                    
                    delay = Utilities.randomize_time("FIN")
                    time.sleep(delay)
            except Exception as e:
                print(f"[!] Error scanning {ip}:{port} - {e}")

        return (str(ip), open_ports)

    
class TCPHostname:
    @staticmethod
    def scan(network, ports, timeout, retries, filename, ftype, max_workers=MAX_WORKERS):
        active_hosts = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = executor.map(lambda ip: TCPHostname._ip_hostname(ip, ports, timeout, retries), network.hosts())

        for hostname, ip, active in results:
            status = "ACTIVE" if active else "INACTIVE"
            active_hosts.append({
                "hostname": hostname,
                "ip": ip,
                "status": status
            })

        return active_hosts

    @staticmethod
    def _ip_hostname(ip, ports, timeout, retries):
        scan = "hostname"
        hostname = resolve_hostname(str(ip))

        for port in ports:
            try:
                for _ in range(retries):
                    src_port = Utilities.randomize_sport()
                    seq_num = Utilities.randomize_seq()
                    window_size = Utilities.randomize_window()
                    ttl_value = Utilities.randomize_ttl()

                    syn_packet = IP(dst=str(ip), ttl=ttl_value) / TCP(
                        sport=src_port, dport=port, flags="S", seq=seq_num, window=window_size)
                    syn_ack_response = sr1(syn_packet, timeout=timeout, verbose=0)

                    if syn_ack_response and syn_ack_response.haslayer(TCP):
                        tcp_layer = syn_ack_response.getlayer(TCP)
                        if tcp_layer.flags & 0x12 == 0x12:
                            ack_seq = seq_num + 1
                            ack_ack = tcp_layer.seq + 1
                            ack_packet = IP(dst=str(ip), ttl=ttl_value) / TCP(
                                sport=src_port, dport=port, flags="A", seq=ack_seq, ack=ack_ack, window=window_size)
                            send(ack_packet, verbose=0)

                            rst_packet = IP(dst=str(ip), ttl=ttl_value) / TCP(
                                sport=src_port, dport=port, flags="R", seq=ack_seq, ack=ack_ack)
                            send(rst_packet, verbose=0)

                            return (hostname, str(ip), True)
                    delay = Utilities.randomize_time(scan)
                    time.sleep(delay)
            except Exception as e:
                print(f"[!] Error scanning {ip}:{port} - {e}")

        return (hostname, str(ip), False)


SCAN_METHODS = {
    "connect": TCPConnectScan.scan,
    "stealth": TCPStealthScan.scan,
    "hostname": TCPHostname.scan,
    "FIN": TCPFINScan.scan
}