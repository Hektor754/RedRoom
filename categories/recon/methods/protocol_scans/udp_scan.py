from scapy.all import IP, UDP, ICMP, sr1
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored
from colorama import init
from ipaddress import ip_network
from utils import handle_scan_output, resolve_hostname
import time

init()

COMMON_UDP_PORTS = [53, 67, 68, 69, 123, 161, 162, 500, 514, 520, 1812, 1813, 3478]


class Output:
    @staticmethod
    def print_udp_banner():
        print("\n" + "-"*60)
        print(colored("[+] Starting UDP host discovery scan", "cyan"))
        print("-"*60)
        print(f"{'Hostname':<20}{'Host':<20}{'Status':<10}")
        print("-"*60)

    @staticmethod
    def print_udp_result(hostname, ip, status):
        status_colors = {
            "ACTIVE": "green",
            "INACTIVE": "red"
        }
        print(f"{hostname:<20}{ip:<20}{colored(status, status_colors.get(status, 'white'))}")

class UDPScan:
    def udp_scan(target_ip, timeout, retries, filename, ftype, silent, max_workers=50, ports=None):
        if ports is None:
            ports = COMMON_UDP_PORTS

        try:
            network = ip_network(target_ip, strict=False)
        except ValueError:
            print(f"[!] Invalid IP or network range: '{target_ip}'")
            return []

        if not silent:
            Output.print_udp_banner()

        targets = [(str(ip), port) for ip in network.hosts() for port in ports]

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = executor.map(lambda ip_port: UDPScan.udp_probe(ip_port[0], ip_port[1], timeout, retries), targets)

        ip_status = {}
        for hostname, ip, active in results:
            if ip not in ip_status or (active and ip_status[ip] == "INACTIVE"):
                ip_status[ip] = "ACTIVE" if active else "INACTIVE"

        active_ips = []
        for ip, status in ip_status.items():
            hostname = resolve_hostname(ip) if status == "ACTIVE" else "Unknown"
            if not silent:
                Output.print_udp_result(hostname, ip, status)
            active_ips.append({
                "hostname": hostname,
                "ip": ip,
                "status": status
            })

        handle_scan_output(active_ips, scantype="UDP", filename=filename, ftype=ftype)

        return active_ips

    def udp_probe(ip, port, timeout, retries):
        hostname = "Unknown"
        pkt = IP(dst=ip)/UDP(dport=port)
        for attempt in range(retries):
            resp = sr1(pkt, timeout=timeout, verbose=0)
            if resp:
                if resp.haslayer(UDP):
                    hostname = resolve_hostname(ip)
                    return (hostname, ip, True)
                elif resp.haslayer(ICMP):
                    icmp_type = resp.getlayer(ICMP).type
                    icmp_code = resp.getlayer(ICMP).code
                    if icmp_type == 3 and icmp_code == 3:
                        hostname = resolve_hostname(ip)
                        return (hostname, ip, True)
            time.sleep(0.1)
        return (hostname, ip, False)