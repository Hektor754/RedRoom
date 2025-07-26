from scapy.all import IP, UDP, ICMP, sr1
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored
from colorama import init
from ipaddress import ip_network
from Essentials.utils import handle_scan_output, resolve_hostname
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

    @staticmethod
    def print_tracert_banner():
        print("\n" + "-" * 60)
        print(colored("[+] Starting Trace Routing with UDP packet probes.", "cyan"))
        print("-" * 60)
        print(f"{'Hop':<5}{'IP':<20}{'Latency':<15}")
        print("-" * 60)
        
    @staticmethod
    def print_udp_tracert_result(ttl, ip, rtt):
        ip_display = ip if ip else "*"
        rtt_display = f"{rtt:.2f} ms" if rtt else "Timeout"
        print(f"{ttl:<5}{ip_display:<20}{rtt_display:<15}")

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
    
class UDPtracert:
    @staticmethod
    def udp_trace(target_ip, timeout, retries, filename, ftype, silent, max_hops=30):
        if not silent:
            Output.print_tracert_banner()

        hops = []
        for ttl in range(1, max_hops + 1):
            ip = None
            rtt = None
            for attempt in range(retries):
                pkt = IP(ttl=ttl) / UDP(dport=33434 + ttl)
                start = time.time()
                resp = sr1(pkt, timeout=timeout, verbose=0)
                rtt = (time.time() - start) * 1000

                if resp:
                    ip = resp.src
                    break

            if not silent:
                Output.print_udp_tracert_result(ttl, ip, rtt)

            hops.append({
                "hop": ttl,
                "ip": ip if ip else "*",
                "rtt": round(rtt, 2) if rtt else None
            })

            if resp and resp.type == 0:
                break
            
            handle_scan_output(hops, scantype="traceroute", filename=filename, ftype=ftype)

        return hops